package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
	ACME   *ACMEConfig `yaml:"acme,omitempty"`

	// Obfuscation (optional, must match client)
	Obfs *ObfsConfig `yaml:"obfs,omitempty"`

	// QUIC tuning
	QUIC *QUICConfig `yaml:"quic,omitempty"`

	// Users with per-user routing and quota
	Users map[string]UserConfig `yaml:"users"`

	// Outbound nodes
	Nodes map[string]NodeConfig `yaml:"nodes"`

	// Management API
	API APIConfig `yaml:"api"`

	// Bandwidth limit (server-wide, optional)
	Bandwidth *BandwidthConfig `yaml:"bandwidth,omitempty"`

	// Masquerade (optional)
	Masquerade *MasqueradeConfig `yaml:"masquerade,omitempty"`

	// SQLite database path for traffic persistence
	DBPath string `yaml:"dbPath,omitempty"`

	// Traffic stats flush interval
	TrafficFlushInterval time.Duration `yaml:"trafficFlushInterval,omitempty"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ACMEConfig struct {
	Domains []string `yaml:"domains"`
	Email   string   `yaml:"email"`
	CA      string   `yaml:"ca,omitempty"`
}

type ObfsConfig struct {
	Type       string `yaml:"type"`
	Salamander struct {
		Password string `yaml:"password"`
	} `yaml:"salamander,omitempty"`
}

type QUICConfig struct {
	InitStreamReceiveWindow     uint64        `yaml:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow      uint64        `yaml:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow       uint64        `yaml:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow        uint64        `yaml:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout              time.Duration `yaml:"maxIdleTimeout,omitempty"`
	MaxIncomingStreams           int64         `yaml:"maxIncomingStreams,omitempty"`
	DisablePathMTUDiscovery     bool          `yaml:"disablePathMTUDiscovery,omitempty"`
}

type BandwidthConfig struct {
	Up   string `yaml:"up,omitempty"`
	Down string `yaml:"down,omitempty"`
}

type MasqueradeConfig struct {
	Type  string `yaml:"type"`
	Proxy struct {
		URL         string `yaml:"url"`
		RewriteHost bool   `yaml:"rewriteHost"`
	} `yaml:"proxy,omitempty"`
}

// UserConfig defines per-user settings.
type UserConfig struct {
	Password string `yaml:"password"`
	// Route is the name of the outbound node, or "direct" for direct connection.
	Route    string `yaml:"route"`
	// MaxBytes is the maximum total traffic (tx+rx) in bytes. 0 means unlimited.
	MaxBytes uint64 `yaml:"maxBytes,omitempty"`
	// SpeedLimit in bytes per second. 0 means unlimited.
	SpeedLimit uint64 `yaml:"speedLimit,omitempty"`
}

// NodeConfig defines an outbound node.
type NodeConfig struct {
	// Type: "direct", "socks5", "http", "hysteria2"
	Type string `yaml:"type"`

	// Direct outbound options
	Direct *DirectConfig `yaml:"direct,omitempty"`

	// SOCKS5 outbound options
	SOCKS5 *SOCKS5Config `yaml:"socks5,omitempty"`

	// HTTP outbound options
	HTTP *HTTPConfig `yaml:"http,omitempty"`

	// Hysteria2 outbound (forward to another hy2 node)
	Hysteria2 *Hysteria2OutboundConfig `yaml:"hysteria2,omitempty"`
}

type DirectConfig struct {
	// Mode: auto, 64, 46, 6, 4
	Mode       string `yaml:"mode,omitempty"`
	BindIPv4   string `yaml:"bindIPv4,omitempty"`
	BindIPv6   string `yaml:"bindIPv6,omitempty"`
	BindDevice string `yaml:"bindDevice,omitempty"`
}

type SOCKS5Config struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type HTTPConfig struct {
	URL      string `yaml:"url"`
	Insecure bool   `yaml:"insecure,omitempty"`
}

type Hysteria2OutboundConfig struct {
	Addr     string `yaml:"addr"`
	Auth     string `yaml:"auth"`
	Insecure bool   `yaml:"insecure,omitempty"`
	SNI      string `yaml:"sni,omitempty"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
	Secret string `yaml:"secret"`
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = ":443"
	}

	if c.TLS.Cert == "" && c.ACME == nil {
		return fmt.Errorf("either tls or acme must be configured")
	}

	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user must be configured")
	}

	for name, user := range c.Users {
		if user.Password == "" {
			return fmt.Errorf("user %q has no password", name)
		}
		if user.Route == "" {
			return fmt.Errorf("user %q has no route", name)
		}
		// Validate route references
		if user.Route != "direct" {
			if _, ok := c.Nodes[user.Route]; !ok {
				return fmt.Errorf("user %q references unknown node %q", name, user.Route)
			}
		}
	}

	for name, node := range c.Nodes {
		switch node.Type {
		case "direct":
			// ok
		case "socks5":
			if node.SOCKS5 == nil || node.SOCKS5.Addr == "" {
				return fmt.Errorf("node %q (socks5) requires addr", name)
			}
		case "http":
			if node.HTTP == nil || node.HTTP.URL == "" {
				return fmt.Errorf("node %q (http) requires url", name)
			}
		case "hysteria2":
			if node.Hysteria2 == nil || node.Hysteria2.Addr == "" {
				return fmt.Errorf("node %q (hysteria2) requires addr and auth", name)
			}
		default:
			return fmt.Errorf("node %q has unknown type %q", name, node.Type)
		}
	}

	if c.TrafficFlushInterval == 0 {
		c.TrafficFlushInterval = 10 * time.Second
	}

	if c.DBPath == "" {
		c.DBPath = "hy2-gateway.db"
	}

	return nil
}
