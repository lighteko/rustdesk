package gateway

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

type DeviceConfig struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	OS                string `json:"os"`
	RustDeskID        string `json:"rustdesk_id"`
	HeartbeatTokenEnv string `json:"heartbeat_token_env"`
}

type Config struct {
	Listen              string         `json:"listen"`
	Origin              string         `json:"origin"`
	Database            string         `json:"database"`
	PublicDir           string         `json:"public_dir"`
	ClientDir           string         `json:"client_dir"`
	BootstrapTokenEnv   string         `json:"bootstrap_token_env"`
	IDUpstream          string         `json:"id_upstream"`
	RelayUpstream       string         `json:"relay_upstream"`
	ServerKey           string         `json:"server_key"`
	EnableRustDeskProxy bool           `json:"enable_rustdesk_proxy"`
	TrustedProxyCIDRs   []string       `json:"trusted_proxy_cidrs"`
	Devices             []DeviceConfig `json:"devices"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c Config) validate() error {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("origin must be a canonical origin without a path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost") {
		return errors.New("HTTPS is required except for http://localhost development")
	}
	if c.Listen == "" || c.Database == "" || c.PublicDir == "" {
		return errors.New("listen, database and public_dir are required")
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return errors.New("invalid trusted proxy CIDR")
		}
	}
	seen := map[string]bool{}
	peers := map[string]bool{}
	for _, d := range c.Devices {
		if d.ID == "" || strings.ContainsAny(d.ID, "/?#\\") || seen[d.ID] || d.RustDeskID == "" || peers[d.RustDeskID] {
			return errors.New("devices require unique device IDs and RustDesk IDs")
		}
		seen[d.ID], peers[d.RustDeskID] = true, true
	}
	if c.EnableRustDeskProxy {
		for _, addr := range []string{c.IDUpstream, c.RelayUpstream} {
			v, err := url.Parse(addr)
			if err != nil || (v.Scheme != "ws" && v.Scheme != "wss") || v.Host == "" || v.User != nil || v.RawQuery != "" || v.Fragment != "" {
				return errors.New("proxy requires fixed ws/wss upstream URLs")
			}
		}
	}
	return nil
}
