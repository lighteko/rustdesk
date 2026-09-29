package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *Server) validSessionLocked(id, owner, device string) (remoteSession, error) {
	v, err := s.readSession(id)
	if err != nil || owner == "" || v.Owner != owner || v.Status != "ACTIVE" || v.RevokedAt != nil || v.Permission != "remote-control" || !time.Now().Before(v.ExpiresAt) {
		return remoteSession{}, errDenied
	}
	a := s.auth[owner]
	if a == nil || !time.Now().Before(a.Expires) {
		return remoteSession{}, errDenied
	}
	if _, ok := s.deviceConfig(v.DeviceID); !ok || (device != "" && v.DeviceID != device) {
		return remoteSession{}, errDenied
	}
	return v, nil
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	device := r.PathValue("device")
	if _, ok := s.deviceConfig(device); !ok {
		fail(w, 404, "device_not_found")
		return
	}
	if a.GrantDevice != device || !time.Now().Before(a.GrantExpires) {
		fail(w, 403, "fresh_device_passkey_required")
		return
	}
	a.GrantDevice = ""
	a.GrantExpires = time.Time{}
	v := remoteSession{ID: randomID("ras_"), DeviceID: device, Owner: owner, Permission: "remote-control", CreatedAt: time.Now(), Status: "ACTIVE", IP: s.requestIP(r), UserAgent: r.UserAgent()}
	v.ExpiresAt = v.CreatedAt.Add(s.ttl)
	if a.Expires.Before(v.ExpiresAt) {
		v.ExpiresAt = a.Expires
	}
	tx, err := s.db.Begin()
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO remote_sessions(id,device_id,owner,permission,created_at,expires_at,status,ip,user_agent) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.DeviceID, v.Owner, v.Permission, v.CreatedAt.UnixMilli(), v.ExpiresAt.UnixMilli(), v.Status, v.IP, v.UserAgent)
	if err == nil {
		err = audit(tx, "REMOTE_SESSION_CREATED", v.ID, device, v.IP, v.UserAgent)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	jsonResponse(w, 201, map[string]any{"session_id": v.ID, "device_id": device, "permission": v.Permission, "expires_at": v.ExpiresAt, "connect_url": "/remote/" + v.ID, "id_socket": "/ws/remote/" + v.ID + "/id", "relay_socket": "/ws/remote/" + v.ID + "/relay"})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	v, err := s.readSession(r.PathValue("session"))
	if err != nil || v.Owner != owner {
		fail(w, 404, "session_not_found")
		return
	}
	if v.Status == "ACTIVE" && !time.Now().Before(v.ExpiresAt) {
		if err = s.terminateLocked(v, "EXPIRED"); err != nil {
			fail(w, 500, "storage_failed")
			return
		}
		v.Status = "EXPIRED"
	}
	jsonResponse(w, 200, v)
}

func (s *Server) connectionConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, _ := s.ownerLocked(r)
	v, err := s.validSessionLocked(r.PathValue("session"), owner, "")
	if err != nil {
		fail(w, 403, "remote_session_denied")
		return
	}
	if !s.cfg.EnableRustDeskProxy {
		fail(w, 503, "rustdesk_adapter_not_enabled")
		return
	}
	d, _ := s.deviceConfig(v.DeviceID)
	base := strings.Replace(s.cfg.Origin, "http", "ws", 1) + "/ws/remote/" + v.ID
	jsonResponse(w, 200, map[string]any{"session_id": v.ID, "device_id": v.DeviceID, "peer_id": d.RustDeskID, "server_key": s.cfg.ServerKey, "id_url": base + "/id", "relay_url": base + "/relay", "expires_at": v.ExpiresAt, "permission": v.Permission, "clipboard": false, "file_transfer": false})
}

func (s *Server) cancelConnectionsLocked(id string) {
	for _, cancel := range s.live[id] {
		cancel()
	}
	for k, v := range s.tickets {
		if v.Session == id {
			delete(s.tickets, k)
		}
	}
}

func (s *Server) terminateLocked(v remoteSession, status string) error {
	// Socket cancellation happens even if storage becomes unavailable.
	defer s.cancelConnectionsLocked(v.ID)
	if v.Status != "ACTIVE" {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revoked any
	if status == "REVOKED" {
		revoked = time.Now().UnixMilli()
	}
	_, err = tx.Exec(`UPDATE remote_sessions SET status=?,revoked_at=? WHERE id=? AND status='ACTIVE'`, status, revoked, v.ID)
	if err == nil {
		err = audit(tx, "REMOTE_SESSION_"+status, v.ID, v.DeviceID, v.IP, v.UserAgent)
	}
	if err == nil {
		err = tx.Commit()
	}
	return err
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	v, err := s.readSession(r.PathValue("session"))
	if err != nil || v.Owner != owner {
		fail(w, 404, "session_not_found")
		return
	}
	status := "REVOKED"
	if !time.Now().Before(v.ExpiresAt) {
		status = "EXPIRED"
	}
	if err = s.terminateLocked(v, status); err != nil {
		fail(w, 500, "revocation_failed")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) activeSessionsLocked(owner string) ([]remoteSession, error) {
	query := `SELECT id FROM remote_sessions WHERE status='ACTIVE'`
	args := []any{}
	if owner != "" {
		query += ` AND owner=?`
		args = append(args, owner)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var out []remoteSession
	for _, id := range ids {
		v, err := s.readSession(id)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) revokeAllLocked() error {
	values, err := s.activeSessionsLocked("")
	if err != nil {
		for id := range s.live {
			s.cancelConnectionsLocked(id)
		}
		return err
	}
	for _, v := range values {
		err = errors.Join(err, s.terminateLocked(v, "REVOKED"))
	}
	return err
}

func (s *Server) invalidateOwnerLocked(owner string) error {
	if owner == "" {
		return nil
	}
	delete(s.auth, owner)
	for k, v := range s.ceremonies {
		if v.Owner == owner {
			delete(s.ceremonies, k)
		}
	}
	values, err := s.activeSessionsLocked(owner)
	if err != nil {
		for id := range s.live {
			s.cancelConnectionsLocked(id)
		}
		return err
	}
	for _, v := range values {
		err = errors.Join(err, s.terminateLocked(v, "REVOKED"))
	}
	return err
}

func (s *Server) killAll(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	// This is a single-owner system: kill sessions from every logged-in browser.
	if err := s.revokeAllLocked(); err != nil {
		fail(w, 500, "revocation_failed")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) attachLocked(v remoteSession, cancel context.CancelFunc) (string, error) {
	if _, err := s.validSessionLocked(v.ID, v.Owner, v.DeviceID); err != nil {
		return "", err
	}
	if len(s.live[v.ID]) >= 4 {
		return "", errDenied
	}
	if s.live[v.ID] == nil {
		s.live[v.ID] = map[string]context.CancelFunc{}
	}
	key := randomID("")
	s.live[v.ID][key] = cancel
	return key, nil
}

func (s *Server) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	values, err := s.activeSessionsLocked("")
	if err != nil {
		for id := range s.live {
			s.cancelConnectionsLocked(id)
		}
		slog.Error("read sessions", "error", err)
		return
	}
	for _, v := range values {
		if !now.Before(v.ExpiresAt) {
			if err := s.terminateLocked(v, "EXPIRED"); err != nil {
				slog.Error("expire session", "error", err)
			}
		}
	}
	for owner, a := range s.auth {
		if !now.Before(a.Expires) {
			if err := s.invalidateOwnerLocked(owner); err != nil {
				slog.Error("invalidate auth", "error", err)
			}
		}
	}
	for k, v := range s.ceremonies {
		if !now.Before(v.Expires) {
			delete(s.ceremonies, k)
		}
	}
	for k, v := range s.tickets {
		if !now.Before(v.Expires) {
			delete(s.tickets, k)
		}
	}
}

type deviceView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	OS              string     `json:"os"`
	Status          string     `json:"status"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	CurrentSessions []string   `json:"current_sessions"`
}

func (s *Server) viewDeviceLocked(d DeviceConfig) (deviceView, error) {
	v := deviceView{ID: d.ID, Name: d.Name, OS: d.OS, Status: "Unknown", CurrentSessions: []string{}}
	var last *int64
	if err := s.db.QueryRow(`SELECT last_seen_at FROM devices WHERE id=?`, d.ID).Scan(&last); err != nil {
		return v, err
	}
	if last != nil {
		t := time.UnixMilli(*last)
		v.LastSeenAt = &t
		v.Status = "Online"
		if time.Since(t) > 45*time.Second {
			v.Status = "Offline"
		}
	}
	rows, err := s.db.Query(`SELECT id FROM remote_sessions WHERE device_id=? AND status='ACTIVE' AND expires_at>?`, d.ID, time.Now().UnixMilli())
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return v, err
		}
		v.CurrentSessions = append(v.CurrentSessions, id)
	}
	return v, rows.Err()
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	out := []deviceView{}
	for _, d := range s.cfg.Devices {
		v, err := s.viewDeviceLocked(d)
		if err != nil {
			fail(w, 500, "storage_failed")
			return
		}
		out = append(out, v)
	}
	jsonResponse(w, 200, out)
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, a := s.ownerLocked(r)
	if a == nil {
		fail(w, 401, "authentication_required")
		return
	}
	d, ok := s.deviceConfig(r.PathValue("device"))
	if !ok {
		fail(w, 404, "device_not_found")
		return
	}
	v, err := s.viewDeviceLocked(d)
	if err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	jsonResponse(w, 200, v)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceConfig(r.PathValue("device"))
	secret := os.Getenv(d.HeartbeatTokenEnv)
	if !ok || len(secret) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+secret)) != 1 {
		fail(w, 403, "agent_denied")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`UPDATE devices SET last_seen_at=?,status='Online' WHERE id=?`, time.Now().UnixMilli(), d.ID); err != nil {
		fail(w, 500, "storage_failed")
		return
	}
	w.WriteHeader(204)
}
