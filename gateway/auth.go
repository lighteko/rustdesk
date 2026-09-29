package gateway

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type ownerUser struct{ Credentials []webauthn.Credential }

func (u ownerUser) WebAuthnID() []byte                         { return []byte("rustdesk-gateway-single-owner") }
func (u ownerUser) WebAuthnName() string                       { return "owner" }
func (u ownerUser) WebAuthnDisplayName() string                { return "Owner" }
func (u ownerUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func (s *Server) ceremonyCookie() string {
	if s.secure {
		return "__Host-rd_ceremony"
	}
	return "rd_ceremony"
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: s.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: s.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func (s *Server) saveCeremony(w http.ResponseWriter, r *http.Request, c ceremony) {
	if old, err := r.Cookie(s.ceremonyCookie()); err == nil {
		delete(s.ceremonies, tokenHash(old.Value))
	}
	token := randomID("")
	c.Expires = time.Now().Add(ceremonyTTL)
	s.ceremonies[tokenHash(token)] = c
	s.setCookie(w, s.ceremonyCookie(), token)
}

func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request) (ceremony, bool) {
	c, err := r.Cookie(s.ceremonyCookie())
	if err != nil {
		return ceremony{}, false
	}
	id := tokenHash(c.Value)
	v, ok := s.ceremonies[id]
	delete(s.ceremonies, id)
	s.clearCookie(w, s.ceremonyCookie())
	return v, ok && time.Now().Before(v.Expires)
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Purpose string `json:"purpose"`
		Device  string `json:"device_id"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, a := s.ownerLocked(r)
	if input.Purpose == "" {
		input.Purpose = "login"
	}
	if input.Purpose != "login" && input.Purpose != "connect" {
		fail(w, 400, "invalid_purpose")
		return
	}
	if input.Purpose == "connect" {
		if a == nil {
			fail(w, 401, "authentication_required")
			return
		}
		if _, ok := s.deviceConfig(input.Device); !ok {
			fail(w, 404, "device_not_found")
			return
		}
	}
	options, data, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintHybrid, protocol.PublicKeyCredentialHintSecurityKey}))
	if err != nil {
		fail(w, 500, "challenge_failed")
		return
	}
	s.saveCeremony(w, r, ceremony{Data: *data, Purpose: input.Purpose, Device: input.Device, Owner: owner})
	jsonResponse(w, 200, options)
}

func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request) {
	if err := audit(s.db, "LOGIN_FAILED", "", "", s.requestIP(r), r.UserAgent()); err != nil {
		fail(w, 500, "audit_failed")
		return
	}
	fail(w, 401, "passkey_verification_failed")
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.takeCeremony(w, r)
	if !ok || (c.Purpose != "login" && c.Purpose != "connect") {
		s.loginFailure(w, r)
		return
	}
	owner, a := s.ownerLocked(r)
	if c.Purpose == "connect" && (a == nil || owner != c.Owner) {
		s.loginFailure(w, r)
		return
	}
	creds, err := s.credentials()
	if err != nil {
		fail(w, 500, "credentials_unavailable")
		return
	}
	user := ownerUser{Credentials: creds}
	_, cred, err := s.wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, user.WebAuthnID()) {
			return nil, errDenied
		}
		for _, v := range creds {
			if bytes.Equal(v.ID, rawID) {
				return user, nil
			}
		}
		return nil, errDenied
	}, c.Data, r)
	if err != nil || cred.Authenticator.CloneWarning {
		s.loginFailure(w, r)
		return
	}
	data, err := json.Marshal(cred)
	if err != nil {
		fail(w, 500, "credential_encoding_failed")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE credentials SET data=? WHERE id=?`, data, credentialID(cred.ID))
	if err == nil {
		err = audit(tx, "LOGIN_SUCCESS", "", c.Device, s.requestIP(r), r.UserAgent())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	if c.Purpose == "login" {
		if a != nil {
			if err = s.invalidateOwnerLocked(owner); err != nil {
				fail(w, 500, "revocation_failed")
				return
			}
		}
		token := randomID("")
		owner = tokenHash(token)
		a = &authSession{}
		s.auth[owner] = a
		s.setCookie(w, s.cookie, token)
	}
	a.Expires = time.Now().Add(s.ttl)
	if c.Purpose == "connect" {
		a.GrantDevice = c.Device
		a.GrantExpires = time.Now().Add(time.Minute)
	}
	jsonResponse(w, 200, map[string]any{"authenticated": true, "expires_at": a.Expires})
}

func (s *Server) bootstrapAllowed(r *http.Request) bool {
	secret := os.Getenv(s.cfg.BootstrapTokenEnv)
	if len(secret) < 32 || subtle.ConstantTimeCompare([]byte(secret), []byte(r.Header.Get("X-Bootstrap-Token"))) != 1 {
		return false
	}
	var count int
	return s.db.QueryRow(`SELECT count(*) FROM credentials`).Scan(&count) == nil && count == 0
}

func (s *Server) registerChallenge(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.bootstrapAllowed(r) {
		fail(w, 403, "bootstrap_denied")
		return
	}
	options, data, err := s.wa.BeginRegistration(ownerUser{})
	if err != nil {
		fail(w, 500, "registration_failed")
		return
	}
	s.saveCeremony(w, r, ceremony{Data: *data, Purpose: "register"})
	jsonResponse(w, 200, options)
}

func (s *Server) registerVerify(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.takeCeremony(w, r)
	if !ok || c.Purpose != "register" || !s.bootstrapAllowed(r) {
		fail(w, 403, "bootstrap_denied")
		return
	}
	cred, err := s.wa.FinishRegistration(ownerUser{}, c.Data, r)
	if err != nil {
		fail(w, 400, "registration_failed")
		return
	}
	data, err := json.Marshal(cred)
	if err != nil {
		fail(w, 500, "credential_encoding_failed")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO credentials(id,data) VALUES(?,?)`, credentialID(cred.ID), data)
	if err == nil {
		err = audit(tx, "PASSKEY_REGISTERED", "", "", s.requestIP(r), r.UserAgent())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	jsonResponse(w, 201, map[string]bool{"registered": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, _ := s.ownerLocked(r)
	// Also invalidate an expired cookie's sessions immediately.
	if owner == "" {
		if c, err := r.Cookie(s.cookie); err == nil {
			owner = tokenHash(c.Value)
		}
	}
	if err := s.invalidateOwnerLocked(owner); err != nil {
		fail(w, 500, "revocation_failed")
		return
	}
	s.clearCookie(w, s.cookie)
	s.clearCookie(w, s.ceremonyCookie())
	w.WriteHeader(204)
}
