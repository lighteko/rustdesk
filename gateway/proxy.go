package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.cfg.Origin {
		fail(w, 403, "invalid_origin")
		return
	}
	kind := r.PathValue("kind")
	if kind != "id" && kind != "relay" {
		fail(w, 403, "invalid_transport")
		return
	}
	s.mu.Lock()
	owner, _ := s.ownerLocked(r)
	v, err := s.validSessionLocked(r.PathValue("session"), owner, r.URL.Query().Get("device_id"))
	if err != nil {
		s.mu.Unlock()
		fail(w, 403, "remote_session_denied")
		return
	}
	if !s.cfg.EnableRustDeskProxy {
		s.mu.Unlock()
		fail(w, 503, "rustdesk_adapter_not_enabled")
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), v.ExpiresAt)
	key, err := s.attachLocked(v, cancel)
	s.mu.Unlock()
	defer cancel()
	if err != nil {
		fail(w, 403, "remote_session_denied")
		return
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.live[v.ID], key)
		if len(s.live[v.ID]) == 0 {
			delete(s.live, v.ID)
		}
		if current, e := s.readSession(v.ID); e == nil && current.Status == "ACTIVE" && !time.Now().Before(current.ExpiresAt) {
			if e = s.terminateLocked(current, "EXPIRED"); e != nil {
				reportError("expire proxy session", e)
			}
		}
		if e := audit(s.db, "REMOTE_SESSION_DISCONNECTED", v.ID, v.DeviceID, s.requestIP(r), r.UserAgent()); e != nil {
			reportError("disconnect audit", e)
		}
	}()
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{s.cfg.Origin}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer client.CloseNow()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			client.CloseNow()
		case <-finished:
		}
	}()
	upstreamURL := s.cfg.IDUpstream
	if kind == "relay" {
		upstreamURL = s.cfg.RelayUpstream
		client.SetReadLimit(16 << 20)
	} else {
		client.SetReadLimit(64 << 10)
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	upstream, response, err := websocket.Dial(dialCtx, upstreamURL, &websocket.DialOptions{HTTPClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	dialCancel()
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		client.Close(websocket.StatusInternalError, "upstream unavailable")
		return
	}
	defer upstream.CloseNow()
	if kind == "relay" {
		upstream.SetReadLimit(16 << 20)
	} else {
		upstream.SetReadLimit(64 << 10)
	}
	go func() {
		select {
		case <-ctx.Done():
			upstream.CloseNow()
		case <-finished:
		}
	}()
	d, _ := s.deviceConfig(v.DeviceID)
	if kind == "relay" {
		handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 5*time.Second)
		typ, data, readErr := client.Read(handshakeCtx)
		handshakeCancel()
		if readErr != nil || typ != websocket.MessageBinary {
			return
		}
		data, err = s.filterRelayHandshake(data, v, d.RustDeskID)
		if err != nil {
			client.Close(websocket.StatusPolicyViolation, "relay access denied")
			return
		}
		if err = upstream.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		s.mu.Lock()
		err = audit(s.db, "REMOTE_SESSION_CONNECTED", v.ID, v.DeviceID, s.requestIP(r), r.UserAgent())
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
	results := make(chan error, 2)
	go func() { results <- s.copySocket(ctx, client, upstream, kind == "id", false, v, d.RustDeskID) }()
	go func() { results <- s.copySocket(ctx, upstream, client, kind == "id", true, v, d.RustDeskID) }()
	<-results
	cancel()
	client.CloseNow()
	upstream.CloseNow()
	<-results
}

func (s *Server) copySocket(ctx context.Context, from, to *websocket.Conn, signal, response bool, v remoteSession, peer string) error {
	for {
		typ, data, err := from.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary {
			return errDenied
		}
		if signal {
			if response {
				data, err = s.filterSignalResponse(data, v, peer)
			} else {
				data, err = s.filterSignal(data, peer)
			}
			if err != nil {
				return err
			}
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = to.Write(ctx, websocket.MessageBinary, data); err != nil {
			return err
		}
	}
}
