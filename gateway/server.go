package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const sessionTTL = 15 * time.Minute
const ceremonyTTL = 2 * time.Minute

type authSession struct {
	Expires      time.Time
	GrantDevice  string
	GrantExpires time.Time
}

type ceremony struct {
	Data    webauthn.SessionData
	Purpose string
	Device  string
	Owner   string
	Expires time.Time
}

type relayTicket struct {
	Session string
	Device  string
	Expires time.Time
}
type rateBucket struct {
	Start time.Time
	Count int
}

type Server struct {
	cfg        Config
	db         *sql.DB
	wa         *webauthn.WebAuthn
	mu         sync.Mutex
	auth       map[string]*authSession
	ceremonies map[string]ceremony
	live       map[string]map[string]context.CancelFunc
	tickets    map[string]relayTicket
	rates      map[string]rateBucket
	cookie     string
	secure     bool
	ttl        time.Duration
}

func New(c Config) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.Origin)
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Remote Access", RPID: u.Hostname(), RPOrigins: []string{c.Origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, err
	}
	db, err := openStore(c.Database)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: c, db: db, wa: wa, auth: map[string]*authSession{}, ceremonies: map[string]ceremony{}, live: map[string]map[string]context.CancelFunc{}, tickets: map[string]relayTicket{}, rates: map[string]rateBucket{}, ttl: sessionTTL, secure: u.Scheme == "https", cookie: "rd_auth"}
	if s.secure {
		s.cookie = "__Host-rd_auth"
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback()
	for _, d := range c.Devices {
		_, err = tx.Exec(`INSERT INTO devices(id,name,os,rustdesk_id,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,os=excluded.os,rustdesk_id=excluded.rustdesk_id,status='Unknown',last_seen_at=NULL`, d.ID, d.Name, d.OS, d.RustDeskID, time.Now().UnixMilli())
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	// In-memory authentication and relay tickets cannot survive a process restart.
	_, err = tx.Exec(`INSERT INTO audit_logs(session_id,device_id,event,ip,user_agent,created_at) SELECT id,device_id,'REMOTE_SESSION_REVOKED',ip,user_agent,? FROM remote_sessions WHERE status='ACTIVE'`, time.Now().UnixMilli())
	if err == nil {
		_, err = tx.Exec(`UPDATE remote_sessions SET status='REVOKED',revoked_at=? WHERE status='ACTIVE'`, time.Now().UnixMilli())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func randomID(prefix string) string {
	return prefix + hex.EncodeToString(randomBytes(32))
}

func randomBytes(n int) []byte {
	v := make([]byte, n)
	// crypto/rand.Read is guaranteed to fill the buffer or terminate the process.
	_, _ = rand.Read(v)
	return v
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conns := range s.live {
		for _, cancel := range conns {
			cancel()
		}
	}
	return s.db.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("POST /api/auth/passkey/challenge", s.challenge)
	mux.HandleFunc("POST /api/auth/passkey/verify", s.verify)
	mux.HandleFunc("POST /api/auth/passkey/register/challenge", s.registerChallenge)
	mux.HandleFunc("POST /api/auth/passkey/register/verify", s.registerVerify)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/capabilities", s.capabilities)
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("GET /api/devices/{device}", s.device)
	mux.HandleFunc("POST /api/devices/{device}/sessions", s.createSession)
	mux.HandleFunc("GET /api/sessions/{session}", s.getSession)
	mux.HandleFunc("GET /api/sessions/{session}/connection", s.connectionConfig)
	mux.HandleFunc("DELETE /api/sessions/{session}", s.deleteSession)
	mux.HandleFunc("DELETE /api/sessions", s.killAll)
	mux.HandleFunc("POST /api/agent/devices/{device}/heartbeat", s.heartbeat)
	mux.HandleFunc("GET /ws/remote/{session}/{kind}", s.proxy)
	if s.cfg.ClientDir != "" {
		mux.Handle("GET /client/", s.requireAuth(http.StripPrefix("/client/", http.FileServer(http.Dir(s.cfg.ClientDir)))))
	}
	files := http.FileServer(http.Dir(s.cfg.PublicDir))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") && !strings.HasPrefix(r.URL.Path, "/remote/") {
			http.NotFound(w, r)
			return
		}
		if _, err := os.Stat(filepath.Join(s.cfg.PublicDir, "index.html")); err != nil {
			fail(w, 503, "portal_not_built")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/remote/") {
			http.ServeFile(w, r, filepath.Join(s.cfg.PublicDir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		if r.Method != "GET" && r.Method != "HEAD" && !strings.HasPrefix(r.URL.Path, "/api/agent/") {
			if r.Header.Get("Origin") != s.cfg.Origin {
				fail(w, 403, "invalid_origin")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if !s.rateLimit(r) {
				w.Header().Set("Retry-After", "60")
				fail(w, 429, "rate_limited")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write response", "error", err)
	}
}
func fail(w http.ResponseWriter, status int, code string) {
	jsonResponse(w, status, map[string]string{"error": code})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func (s *Server) ownerLocked(r *http.Request) (string, *authSession) {
	c, err := r.Cookie(s.cookie)
	if err != nil {
		return "", nil
	}
	id := tokenHash(c.Value)
	a := s.auth[id]
	if a == nil || !time.Now().Before(a.Expires) {
		return "", nil
	}
	return id, a
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		_, a := s.ownerLocked(r)
		s.mu.Unlock()
		if a == nil {
			fail(w, 401, "authentication_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	jsonResponse(w, 200, map[string]any{"expires_at": a.Expires})
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	_, a := s.ownerLocked(r)
	s.mu.Unlock()
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	_, err := os.Stat(filepath.Join(s.cfg.ClientDir, "adapter.js"))
	ready := s.cfg.EnableRustDeskProxy && s.cfg.ClientDir != "" && err == nil
	jsonResponse(w, 200, map[string]any{"remote_desktop": ready, "session_ttl_seconds": int(sessionTTL.Seconds()), "clipboard": false, "file_transfer": false})
}

func (s *Server) rateLimit(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	group := "api"
	limit := 180
	if strings.Contains(r.URL.Path, "/auth/") {
		group = "auth"
		limit = 20
	}
	if strings.HasPrefix(r.URL.Path, "/ws/") {
		group = "connect"
		limit = 30
	}
	if strings.Contains(r.URL.Path, "sessions") {
		group = "sessions"
		limit = 60
	}
	key := s.requestIP(r) + ":" + group
	now := time.Now()
	for k, v := range s.rates {
		if now.Sub(v.Start) > time.Minute {
			delete(s.rates, k)
		}
	}
	if len(s.rates) >= 10000 {
		return false
	}
	v := s.rates[key]
	if v.Start.IsZero() {
		v.Start = now
	}
	v.Count++
	s.rates[key] = v
	return v.Count <= limit
}

func (s *Server) deviceConfig(id string) (DeviceConfig, bool) {
	for _, d := range s.cfg.Devices {
		if d.ID == id {
			return d, true
		}
	}
	return DeviceConfig{}, false
}

var errDenied = errors.New("session access denied")

func (s *Server) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func credentialID(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
