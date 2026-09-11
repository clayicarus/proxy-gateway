package config

import (
	"fmt"
	"os"
	"time"
	_ "time/tzdata" // Keep named zones available without an OS timezone database.

	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	// Inbounds is populated by LoadRuntime. Listen and QUIC remain a
	// compatibility projection of the first/subscription-bound inbound for the
	// existing management and subscription read models.
	Inbounds []Inbound `yaml:"-"`
	Listen   string    `yaml:"listen"`
	TLS      TLSConfig `yaml:"tls"`

	// Deprecated: retained only to reject a configuration that the data plane
	// never implemented.
	Obfs *ObfsConfig `yaml:"obfs,omitempty"`

	// QUIC tuning
	QUIC *QUICConfig `yaml:"quic,omitempty"`

	// Users with per-user routing and quota
	//
	// Deprecated: only read by the explicit `migrate` command. Runtime users
	// are stored in SQLite.
	Users map[string]UserConfig `yaml:"users"`

	// Outbound nodes
	//
	// Deprecated: only read by the explicit `migrate` command. Runtime nodes
	// are stored in SQLite.
	Nodes map[string]NodeConfig `yaml:"nodes"`

	// API is retained only for legacy listener and subscription-secret migration.
	API APIConfig `yaml:"api"`

	// Admin is the loopback-only management web listener. API is retained so
	// legacy configurations can be migrated without losing their listener.
	Admin AdminConfig `yaml:"admin,omitempty"`

	// Subscription config for generating client configs
	Sub *SubConfig `yaml:"sub,omitempty"`

	// Deprecated: legacy top-level field, read only by the management-data
	// migration path. The runtime schema configures masquerade per inbound in
	// Inbound.Masquerade; this field is not consulted by the data plane.
	Masquerade *MasqueradeConfig `yaml:"masquerade,omitempty"`

	// SQLite database path for traffic persistence
	DBPath string `yaml:"dbPath,omitempty"`

	// Traffic stats flush interval
	TrafficFlushInterval time.Duration `yaml:"trafficFlushInterval,omitempty"`

	// Timezone controls natural-month usage boundaries. Timestamps in SQLite
	// are always stored as UTC Unix timestamps.
	Timezone string `yaml:"timezone,omitempty"`

	// Optional systemd integration for restart requests and watchdog support.
	Systemd *SystemdConfig `yaml:"systemd,omitempty"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ObfsConfig struct {
	Type       string `yaml:"type"`
	Salamander struct {
		Password string `yaml:"password"`
	} `yaml:"salamander,omitempty"`
}

type QUICConfig struct {
	InitStreamReceiveWindow uint64        `yaml:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64        `yaml:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64        `yaml:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64        `yaml:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          time.Duration `yaml:"maxIdleTimeout,omitempty"`
	MaxIncomingStreams      int64         `yaml:"maxIncomingStreams,omitempty"`
	DisablePathMTUDiscovery bool          `yaml:"disablePathMTUDiscovery,omitempty"`
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
	// Disabled and ExpiresAt are runtime-only fields populated from SQLite.
	Disabled  bool       `yaml:"-"`
	ExpiresAt *time.Time `yaml:"-"`
	// Routes is the list of outbound node names this user can access.
	// "direct" is a special value meaning direct connection.
	Routes []string `yaml:"routes"`
	// MaxBytes is the maximum total traffic (tx+rx) in bytes across all nodes. 0 means unlimited.
	MaxBytes uint64 `yaml:"maxBytes,omitempty"`
	// SpeedLimit in bytes per second. 0 means unlimited.
	SpeedLimit uint64 `yaml:"speedLimit,omitempty"`
}

// NodeConfig defines an outbound node.
type NodeConfig struct {
	// Type is currently always "hysteria2" for managed nodes.
	Type string `yaml:"type"`

	// Alias is an optional display name used in generated subscription configs.
	// If empty, the node key name is used.
	Alias string `yaml:"alias,omitempty"`

	// Hysteria2 outbound (forward to another hy2 node)
	Hysteria2 *Hysteria2OutboundConfig `yaml:"hysteria2,omitempty"`
}

type Hysteria2OutboundConfig struct {
	Addr     string `yaml:"addr"`
	Auth     string `yaml:"auth"`
	Insecure bool   `yaml:"insecure,omitempty"`
	SNI      string `yaml:"sni,omitempty"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
	// Secret is only used when importing legacy HMAC subscription tokens.
	Secret string `yaml:"secret"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"`
}

type SystemdConfig struct {
	Unit     string `yaml:"unit,omitempty"`
	Watchdog bool   `yaml:"watchdog,omitempty"`
}

// SubConfig defines subscription endpoint settings.
type SubConfig struct {
	// Secret used to generate per-user tokens (HMAC key).
	// If empty, falls back to api.secret.
	Secret string `yaml:"secret,omitempty"`
	// Listen is the public HTTP listener for subscription URLs. It is separate
	// from the loopback-only management listener.
	Listen string `yaml:"listen,omitempty"`
	// PublicURL is the externally reachable base URL for subscription links,
	// for example https://sub.example.com/sub/.
	PublicURL string `yaml:"publicURL,omitempty"`
	// ServerAddr is the public address of the gateway that clients connect to,
	// e.g. "your.domain.com:8443". Used in generated proxy configs.
	ServerAddr string `yaml:"serverAddr"`
	// SNI override for the generated client config (optional).
	SNI string `yaml:"sni,omitempty"`
	// Insecure skips TLS verification in generated client config (for self-signed certs).
	Insecure bool   `yaml:"insecure,omitempty"`
	Inbound  string `yaml:"inbound,omitempty"`
	// Endpoints publishes several named inbounds through one subscription.
	Endpoints []SubscriptionEndpoint `yaml:"endpoints,omitempty"`
}

// ClientEndpoints returns the explicit endpoints advertised to clients. The
// original single-inbound fields remain supported for existing configurations.
func (s *SubConfig) ClientEndpoints() []SubscriptionEndpoint {
	if s == nil {
		return nil
	}
	if s.Endpoints != nil {
		return append([]SubscriptionEndpoint(nil), s.Endpoints...)
	}
	return []SubscriptionEndpoint{{
		Inbound: s.Inbound, ServerAddr: s.ServerAddr,
		SNI: s.SNI, Insecure: s.Insecure,
	}}
}

// LoadRuntime reads the only schema accepted by the gateway data plane.
func LoadRuntime(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	inbound, err := ParseInboundConfig(data)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Inbounds:             append([]Inbound(nil), inbound.Inbounds...),
		TLS:                  inbound.TLS,
		Admin:                inbound.Admin,
		DBPath:               inbound.DBPath,
		TrafficFlushInterval: inbound.TrafficFlushInterval,
		Timezone:             inbound.Timezone,
		Systemd:              inbound.Systemd,
	}
	if len(cfg.Inbounds) > 0 {
		cfg.Listen = cfg.Inbounds[0].Listen
		cfg.QUIC = cfg.Inbounds[0].QUIC
	}
	if inbound.Sub != nil {
		single := SubscriptionEndpoint{}
		if inbound.Sub.SubscriptionEndpoint != nil {
			single = *inbound.Sub.SubscriptionEndpoint
		}
		cfg.Sub = &SubConfig{
			Listen: inbound.Sub.Listen, PublicURL: inbound.Sub.PublicURL,
			Inbound: single.Inbound, ServerAddr: single.ServerAddr,
			SNI: single.SNI, Insecure: single.Insecure,
			Endpoints: append([]SubscriptionEndpoint(nil), inbound.Sub.Endpoints...),
		}
		primaryInbound := cfg.Sub.ClientEndpoints()[0].Inbound
		for i := range cfg.Inbounds {
			if cfg.Inbounds[i].Name == primaryInbound {
				cfg.Listen = cfg.Inbounds[i].Listen
				cfg.QUIC = cfg.Inbounds[i].QUIC
				break
			}
		}
	}
	return cfg, nil
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	if hasTopLevelKey(&root, "obfs") {
		return nil, fmt.Errorf("config validation failed: obfs is not supported by the Gateway data plane; remove obfs before starting")
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
	if c.Obfs != nil {
		return fmt.Errorf("obfs is not supported by the Gateway data plane; remove obfs before starting")
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}

	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("tls.cert and tls.key must be configured")
	}

	if c.Timezone == "" {
		c.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", c.Timezone, err)
	}

	if c.Systemd != nil {
		if c.Systemd.Unit == "" {
			c.Systemd.Unit = "proxy-gateway.service"
		}
	}
	if c.TrafficFlushInterval == 0 {
		c.TrafficFlushInterval = 10 * time.Second
	}
	if c.DBPath == "" {
		c.DBPath = "proxy-gateway.db"
	}

	return nil
}

// ValidateLegacy validates the deprecated static user/node data used only by
// the one-time migration command.
func (c *Config) ValidateLegacy() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one legacy user must be configured")
	}

	for name, user := range c.Users {
		if user.Password == "" {
			return fmt.Errorf("user %q has no password", name)
		}
		if len(user.Routes) == 0 {
			return fmt.Errorf("user %q has no routes", name)
		}
		for _, route := range user.Routes {
			if route != "direct" {
				if _, ok := c.Nodes[route]; !ok {
					return fmt.Errorf("user %q references unknown node %q", name, route)
				}
			}
		}
	}

	for name, node := range c.Nodes {
		if node.Type != "hysteria2" {
			return fmt.Errorf("node %q has unknown type %q", name, node.Type)
		}
		if node.Hysteria2 == nil || node.Hysteria2.Addr == "" || node.Hysteria2.Auth == "" {
			return fmt.Errorf("node %q (hysteria2) requires addr and auth", name)
		}
	}

	return nil
}
