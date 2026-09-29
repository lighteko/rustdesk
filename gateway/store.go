package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

type remoteSession struct {
	ID         string     `json:"session_id"`
	DeviceID   string     `json:"device_id"`
	Permission string     `json:"permission"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Status     string     `json:"status"`
	Owner      string     `json:"-"`
	IP         string     `json:"-"`
	UserAgent  string     `json:"-"`
}

func openStore(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT NOT NULL, rustdesk_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Unknown', last_seen_at INTEGER, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_sessions (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), owner TEXT NOT NULL, permission TEXT NOT NULL CHECK(permission='remote-control'), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER, status TEXT NOT NULL CHECK(status IN ('ACTIVE','EXPIRED','REVOKED')), ip TEXT NOT NULL, user_agent TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_owner ON remote_sessions(owner, status);
CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, device_id TEXT NOT NULL, event TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT NOT NULL, created_at INTEGER NOT NULL);
`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

type sqlExecutor interface {
	Exec(string, ...any) (sql.Result, error)
}

func audit(e sqlExecutor, event, session, device, ip, ua string) error {
	_, err := e.Exec(`INSERT INTO audit_logs(session_id,device_id,event,ip,user_agent,created_at) VALUES(?,?,?,?,?,?)`, session, device, event, ip, ua, time.Now().UnixMilli())
	return err
}

func (s *Server) requestIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	for _, cidr := range s.cfg.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(addr.Unmap()) {
			// Caddy must overwrite this header with its actual TCP peer address.
			forwarded, err := netip.ParseAddr(r.Header.Get("X-Real-IP"))
			if err == nil {
				return forwarded.Unmap().String()
			}
		}
	}
	return ip
}

func (s *Server) readSession(id string) (remoteSession, error) {
	var v remoteSession
	var created, expires int64
	var revoked sql.NullInt64
	err := s.db.QueryRow(`SELECT id,device_id,owner,permission,created_at,expires_at,revoked_at,status,ip,user_agent FROM remote_sessions WHERE id=?`, id).Scan(&v.ID, &v.DeviceID, &v.Owner, &v.Permission, &created, &expires, &revoked, &v.Status, &v.IP, &v.UserAgent)
	v.CreatedAt, v.ExpiresAt = time.UnixMilli(created), time.UnixMilli(expires)
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64)
		v.RevokedAt = &t
	}
	return v, err
}

func (s *Server) credentials() ([]webauthn.Credential, error) {
	rows, err := s.db.Query(`SELECT data FROM credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var data []byte
		var v webauthn.Credential
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("decode credential: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
