package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type virtualPasskey struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}
type browser struct {
	t       *testing.T
	s       *Server
	cookies map[string]*http.Cookie
	key     *virtualPasskey
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	c := Config{Listen: "127.0.0.1:8080", Origin: "http://localhost:8080", Database: filepath.Join(t.TempDir(), "gateway.db"), PublicDir: "web/dist", BootstrapTokenEnv: "TEST_RD_BOOTSTRAP", Devices: []DeviceConfig{{ID: "main-pc", Name: "Main PC", OS: "Windows", RustDeskID: "111111"}, {ID: "macbook", Name: "MacBook", OS: "macOS", RustDeskID: "222222"}}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func newBrowser(t *testing.T, s *Server) *browser {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, s: s, cookies: map[string]*http.Cookie{}, key: &virtualPasskey{key: key, id: randomBytes(32)}}
}

func (b *browser) request(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		b.t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Origin", b.s.cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	for name, v := range headers {
		r.Header.Set(name, v)
	}
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.s.Handler().ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d, want %d: %s", w.Code, status, w.Body.String())
	}
}
func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
func challengeValue(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	expect(t, w, 200)
	var v struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.PublicKey.Challenge
}

func (b *browser) clientData(typ, challenge string) []byte {
	v, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": b.s.cfg.Origin, "crossOrigin": false})
	if err != nil {
		b.t.Fatal(err)
	}
	return v
}

func (b *browser) enroll() {
	b.t.Helper()
	secret := strings.Repeat("b", 40)
	b.t.Setenv("TEST_RD_BOOTSTRAP", secret)
	headers := map[string]string{"X-Bootstrap-Token": secret}
	challenge := challengeValue(b.t, b.request("POST", "/api/auth/passkey/register/challenge", nil, headers))
	key := b.key.key
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		b.t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("localhost"))
	data := append(rp[:], byte(0x45)) // user present, verified, attested credential data
	data = append(data, make([]byte, 4+16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(b.key.id)))
	data = append(data, b.key.id...)
	data = append(data, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if err != nil {
		b.t.Fatal(err)
	}
	body := map[string]any{"id": b64(b.key.id), "rawId": b64(b.key.id), "type": "public-key", "response": map[string]any{"clientDataJSON": b64(b.clientData("webauthn.create", challenge)), "attestationObject": b64(attestation)}}
	expect(b.t, b.request("POST", "/api/auth/passkey/register/verify", body, headers), 201)
	expect(b.t, b.request("POST", "/api/auth/passkey/register/challenge", nil, headers), 403)
}

func (b *browser) assertion(challenge string, verified bool) map[string]any {
	b.key.count++
	rp := sha256.Sum256([]byte("localhost"))
	flags := byte(1)
	if verified {
		flags |= 4
	}
	data := append(rp[:], flags)
	data = binary.BigEndian.AppendUint32(data, b.key.count)
	client := b.clientData("webauthn.get", challenge)
	clientHash := sha256.Sum256(client)
	toSign := append(append([]byte{}, data...), clientHash[:]...)
	h := sha256.Sum256(toSign)
	sig, err := ecdsa.SignASN1(rand.Reader, b.key.key, h[:])
	if err != nil {
		b.t.Fatal(err)
	}
	return map[string]any{"id": b64(b.key.id), "rawId": b64(b.key.id), "type": "public-key", "response": map[string]any{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(sig), "userHandle": b64(ownerUser{}.WebAuthnID())}}
}

func (b *browser) authenticate(device string) {
	b.t.Helper()
	purpose := "login"
	if device != "" {
		purpose = "connect"
	}
	w := b.request("POST", "/api/auth/passkey/challenge", map[string]any{"purpose": purpose, "device_id": device}, nil)
	challenge := challengeValue(b.t, w)
	if !strings.Contains(w.Body.String(), `"userVerification":"required"`) {
		b.t.Fatal("user verification must be required")
	}
	expect(b.t, b.request("POST", "/api/auth/passkey/verify", b.assertion(challenge, true), nil), 200)
}

func (b *browser) session(device string) remoteSession {
	b.t.Helper()
	b.authenticate(device)
	w := b.request("POST", "/api/devices/"+device+"/sessions", nil, nil)
	expect(b.t, w, 201)
	var v remoteSession
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		b.t.Fatal(err)
	}
	return v
}

func TestPasskeyAndPerDeviceSingleUseGrant(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.enroll()
	b.authenticate("")
	cookie := b.cookies[s.cookie]
	if cookie == nil || !cookie.HttpOnly || cookie.MaxAge != 0 || !cookie.Expires.IsZero() || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("authentication must use an HttpOnly, nonpersistent, Strict cookie")
	}
	expect(t, b.request("POST", "/api/devices/main-pc/sessions", nil, nil), 403)
	b.authenticate("main-pc")
	expect(t, b.request("POST", "/api/devices/macbook/sessions", nil, nil), 403)
	expect(t, b.request("POST", "/api/devices/main-pc/sessions", nil, nil), 201)
	expect(t, b.request("POST", "/api/devices/main-pc/sessions", nil, nil), 403)
	expect(t, b.request("POST", "/api/devices/main-pc/sessions", nil, map[string]string{"Origin": "https://evil.example"}), 403)
	w := b.request("GET", "/api/devices", nil, nil)
	expect(t, w, 200)
	if strings.Contains(w.Body.String(), "111111") || !strings.Contains(w.Body.String(), "Unknown") {
		t.Fatal("device view must hide peer ID and avoid invented online state")
	}
}

func TestPasskeyRejectsMissingUVReplayAndTampering(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.enroll()
	challenge := challengeValue(t, b.request("POST", "/api/auth/passkey/challenge", map[string]string{"purpose": "login"}, nil))
	assertion := b.assertion(challenge, false)
	expect(t, b.request("POST", "/api/auth/passkey/verify", assertion, nil), 401)
	expect(t, b.request("POST", "/api/auth/passkey/verify", assertion, nil), 401)
	challenge = challengeValue(t, b.request("POST", "/api/auth/passkey/challenge", map[string]string{"purpose": "login"}, nil))
	assertion = b.assertion(challenge, true)
	assertion["response"].(map[string]any)["signature"] = b64([]byte("forged signature"))
	expect(t, b.request("POST", "/api/auth/passkey/verify", assertion, nil), 401)
	expect(t, b.request("GET", "/api/me", nil, nil), 401)
}

type upstreamFixture struct {
	ID       string
	Relay    string
	Attempts *atomic.Int32
}

func upstreamServers(t *testing.T) upstreamFixture {
	t.Helper()
	attempts := &atomic.Int32{}
	id := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			tag, f, err := parseEnvelope(data)
			if err != nil || (tag != 8 && tag != 18) || f.text(1) != "111111" {
				return
			}
			if tag == 8 && f.number(8) != 1 {
				t.Error("gateway failed to force relay")
				return
			}
			out := textField(nil, 2, uuid.NewString())
			out = textField(out, 4, "111111")
			if err := conn.Write(ctx, websocket.MessageBinary, envelope(19, out)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(id.Close)
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, err = conn.Read(ctx); err != nil {
			return
		} // consume the relay handshake
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if err = conn.Write(ctx, typ, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(relay.Close)
	return upstreamFixture{ID: strings.Replace(id.URL, "http", "ws", 1), Relay: strings.Replace(relay.URL, "http", "ws", 1), Attempts: attempts}
}

func (b *browser) socket(t *testing.T, base, id, kind string) *websocket.Conn {
	t.Helper()
	headers := http.Header{"Origin": []string{b.s.cfg.Origin}}
	r := &http.Request{Header: headers}
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(base, "http", "ws", 1)+"/ws/remote/"+id+"/"+kind, &websocket.DialOptions{HTTPHeader: r.Header})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func (b *browser) relay(t *testing.T, base string, v remoteSession) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id := b.socket(t, base, v.ID, "id")
	if err := id.Write(ctx, websocket.MessageBinary, envelope(8, textField(nil, 1, "111111"))); err != nil {
		t.Fatal(err)
	}
	_, data, err := id.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, f, err := parseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	relay := b.socket(t, base, v.ID, "relay")
	handshake := textField(nil, 1, "111111")
	handshake = textField(handshake, 2, f.text(2))
	if err := relay.Write(ctx, websocket.MessageBinary, envelope(18, handshake)); err != nil {
		t.Fatal(err)
	}
	if err := relay.Write(ctx, websocket.MessageBinary, []byte("encrypted screen/input")); err != nil {
		t.Fatal(err)
	}
	_, data, err = relay.Read(ctx)
	if err != nil || string(data) != "encrypted screen/input" {
		t.Fatalf("relay failed: %s %v", data, err)
	}
	return relay
}

func TestProxyDeniesLeakedURLsWrongDeviceAndOrigin(t *testing.T) {
	s := newTestServer(t)
	upstream := upstreamServers(t)
	s.cfg.EnableRustDeskProxy = true
	s.cfg.IDUpstream = upstream.ID
	s.cfg.RelayUpstream = upstream.Relay
	b := newBrowser(t, s)
	b.enroll()
	b.authenticate("")
	v := b.session("main-pc")
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	for _, tc := range []struct {
		name, origin, device string
		authenticated        bool
	}{
		{"leaked URL", s.cfg.Origin, "", false}, {"wrong origin", "https://evil.example", "", true}, {"wrong device", s.cfg.Origin, "macbook", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Origin": []string{tc.origin}}
			if tc.authenticated {
				r := &http.Request{Header: headers}
				for _, c := range b.cookies {
					r.AddCookie(c)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, response, err := websocket.Dial(ctx, strings.Replace(server.URL, "http", "ws", 1)+"/ws/remote/"+v.ID+"/id?device_id="+tc.device, &websocket.DialOptions{HTTPHeader: headers})
			if conn != nil {
				conn.CloseNow()
			}
			if err == nil || response == nil || response.StatusCode != 403 {
				t.Fatalf("expected 403: %v %v", response, err)
			}
		})
	}
	if upstream.Attempts.Load() != 0 {
		t.Fatal("denied requests reached RustDesk")
	}
	conn := b.socket(t, server.URL, v.ID, "id")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, envelope(8, textField(nil, 1, "222222"))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("cross-device signaling was accepted")
	}
}

func TestEstablishedRelayClosesOnRevokeExpiryLogoutAndKillAll(t *testing.T) {
	for _, action := range []string{"revoke", "expiry", "logout", "kill-all"} {
		t.Run(action, func(t *testing.T) {
			s := newTestServer(t)
			upstream := upstreamServers(t)
			s.cfg.EnableRustDeskProxy = true
			s.cfg.IDUpstream = upstream.ID
			s.cfg.RelayUpstream = upstream.Relay
			if action == "expiry" {
				s.ttl = 800 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go s.Run(ctx)
			b := newBrowser(t, s)
			b.enroll()
			b.authenticate("")
			v := b.session("main-pc")
			server := httptest.NewServer(s.Handler())
			defer server.Close()
			conn := b.relay(t, server.URL, v)
			switch action {
			case "revoke":
				expect(t, b.request("DELETE", "/api/sessions/"+v.ID, nil, nil), 204)
			case "logout":
				expect(t, b.request("POST", "/api/logout", nil, nil), 204)
			case "kill-all":
				other := newBrowser(t, s)
				other.key = b.key
				other.authenticate("")
				expect(t, other.request("DELETE", "/api/sessions", nil, nil), 204)
			}
			readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer readCancel()
			_, _, err := conn.Read(readCtx)
			if err == nil || readCtx.Err() != nil {
				t.Fatalf("idle socket was not forcibly terminated: %v", err)
			}
			if action == "expiry" {
				time.Sleep(20 * time.Millisecond)
			}
			s.mu.Lock()
			row, err := s.readSession(v.ID)
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			want := "REVOKED"
			if action == "expiry" {
				want = "EXPIRED"
			}
			if row.Status != want {
				t.Fatalf("status %s, want %s", row.Status, want)
			}
			headers := http.Header{"Origin": []string{s.cfg.Origin}}
			request := &http.Request{Header: headers}
			for _, cookie := range b.cookies {
				request.AddCookie(cookie)
			}
			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			defer dialCancel()
			newConn, response, dialErr := websocket.Dial(dialCtx, strings.Replace(server.URL, "http", "ws", 1)+"/ws/remote/"+v.ID+"/relay", &websocket.DialOptions{HTTPHeader: headers})
			if newConn != nil {
				newConn.CloseNow()
			}
			if dialErr == nil || response == nil || response.StatusCode != 403 {
				t.Fatal("terminated session allowed a new connection")
			}
			var count int
			if err = s.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE session_id=? AND event=?`, v.ID, "REMOTE_SESSION_"+want).Scan(&count); err != nil || count != 1 {
				t.Fatalf("missing/duplicate terminal audit: %d %v", count, err)
			}
		})
	}
}

func TestForwardedIPRequiresTrustedProxy(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest("GET", "/api/devices", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Real-IP", "198.51.100.20")
	if got := s.requestIP(r); got != "192.0.2.10" {
		t.Fatalf("spoofed forwarding header trusted: %s", got)
	}
	s.cfg.TrustedProxyCIDRs = []string{"192.0.2.10/32"}
	if got := s.requestIP(r); got != "198.51.100.20" {
		t.Fatalf("trusted edge IP not recorded: %s", got)
	}
}

func TestProtocolRejectsICEFileTransferAndRelayTicketReuse(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.enroll()
	b.authenticate("")
	v := b.session("main-pc")
	for _, data := range [][]byte{
		envelope(8, textField(textField(nil, 1, "111111"), 12, "webrtc://offer")),
		envelope(8, numberField(textField(nil, 1, "111111"), 4, 1)),
		envelope(15, textField(nil, 1, "111111")),
		envelope(8, textField(textField(nil, 1, "222222"), 1, "111111")),
		[]byte("encrypted signaling"),
	} {
		if _, err := s.filterSignal(data, "111111"); err == nil {
			t.Fatal("unsafe signaling accepted")
		}
	}
	// Use the persisted record so ownership is checked too.
	s.mu.Lock()
	stored, err := s.readSession(v.ID)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ticket := uuid.NewString()
	response := envelope(19, textField(textField(nil, 2, ticket), 4, "111111"))
	if _, err = s.filterSignalResponse(response, stored, "111111"); err != nil {
		t.Fatal(err)
	}
	handshake := envelope(18, textField(textField(nil, 1, "111111"), 2, ticket))
	if _, err = s.filterRelayHandshake(handshake, stored, "111111"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.filterRelayHandshake(handshake, stored, "111111"); err == nil {
		t.Fatal("relay ticket reused")
	}
}

func TestRestartRevokesPersistedSession(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.enroll()
	b.authenticate("")
	v := b.session("main-pc")
	// Open a second instance only after the first instance has stopped serving.
	other, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	row, err := other.readSession(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "REVOKED" {
		t.Fatal("restart retained an active session")
	}
	if _, err = other.validSessionLocked(v.ID, row.Owner, ""); err == nil {
		t.Fatal("restart accepted stale authority")
	}
}
