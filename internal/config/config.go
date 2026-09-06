package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`

	// Trojan is an optional TCP/TLS inbound. It can share the numeric port
	// with Listen because Hysteria2 uses UDP while Trojan uses TCP.
	Trojan *TrojanConfig `yaml:"trojan,omitempty"`

	// Obfuscation (optional, must match client)
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

	// Masquerade (optional)
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

const (
	DefaultTrojanHandshakeTimeout      = 10 * time.Second
	DefaultTrojanMaxPendingConnections = 256
)

// TrojanConfig controls the first-phase Trojan TCP CONNECT inbound.
// Client subscription metadata deliberately remains out of this contract
// until Trojan subscriptions are implemented.
type TrojanConfig struct {
	Listen                string        `yaml:"listen,omitempty"`
	HandshakeTimeout      time.Duration `yaml:"handshakeTimeout,omitempty"`
	MaxPendingConnections int           `yaml:"maxPendingConnections,omitempty"`
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
	Insecure bool `yaml:"insecure,omitempty"`
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("failed to parse config file: multiple YAML documents are not supported")
		}
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
	if c.TrafficFlushInterval < 0 {
		return fmt.Errorf("trafficFlushInterval must be greater than zero")
	}
	if c.DBPath == "" {
		c.DBPath = "proxy-gateway.db"
	}
	if c.Obfs != nil {
		return fmt.Errorf("obfs is not supported by the gateway; remove the obfs block")
	}
	if c.Masquerade != nil {
		return fmt.Errorf("masquerade is not supported by the gateway; remove the masquerade block")
	}
	if c.Sub != nil && (c.Sub.Listen != "" || c.Sub.PublicURL != "" || c.Sub.ServerAddr != "") {
		if err := validateTCPListen(c.Sub.ServerAddr); err != nil {
			return fmt.Errorf("sub.serverAddr must explicitly specify the client-facing host and port: %w", err)
		}
		host, _, _ := net.SplitHostPort(c.Sub.ServerAddr)
		if isWildcardHost(normalizeListenHost(host)) {
			return fmt.Errorf("sub.serverAddr must use a client-facing host, not a wildcard listen address")
		}
	}

	if c.Trojan != nil && c.Trojan.Listen != "" {
		if err := validateTCPListen(c.Trojan.Listen); err != nil {
			return fmt.Errorf("invalid trojan.listen %q: %w", c.Trojan.Listen, err)
		}
		if c.Trojan.HandshakeTimeout == 0 {
			c.Trojan.HandshakeTimeout = DefaultTrojanHandshakeTimeout
		}
		if c.Trojan.HandshakeTimeout < time.Second || c.Trojan.HandshakeTimeout > 2*time.Minute {
			return fmt.Errorf("trojan.handshakeTimeout must be between 1s and 2m")
		}
		if c.Trojan.MaxPendingConnections == 0 {
			c.Trojan.MaxPendingConnections = DefaultTrojanMaxPendingConnections
		}
		if c.Trojan.MaxPendingConnections < 1 || c.Trojan.MaxPendingConnections > 65535 {
			return fmt.Errorf("trojan.maxPendingConnections must be between 1 and 65535")
		}

		adminListen := c.Admin.Listen
		if adminListen == "" {
			adminListen = c.API.Listen
		}
		for name, listen := range map[string]string{
			"admin.listen": adminListen,
			"sub.listen":   subListen(c.Sub),
		} {
			if listen != "" && tcpListensConflict(c.Trojan.Listen, listen) {
				return fmt.Errorf("trojan.listen conflicts with %s", name)
			}
		}
	}

	return nil
}

func subListen(sub *SubConfig) string {
	if sub == nil {
		return ""
	}
	return sub.Listen
}

func validateTCPListen(addr string) error {
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be an integer between 1 and 65535")
	}
	if strings.ContainsRune(host, '\x00') {
		return fmt.Errorf("host contains NUL")
	}
	return nil
}

func tcpListensConflict(a, b string) bool {
	aHost, aPort, errA := net.SplitHostPort(a)
	bHost, bPort, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil {
		return false
	}
	aNumber, aErr := strconv.Atoi(aPort)
	bNumber, bErr := strconv.Atoi(bPort)
	if aErr != nil || bErr != nil || aNumber != bNumber {
		return false
	}
	aHost = normalizeListenHost(aHost)
	bHost = normalizeListenHost(bHost)
	return aHost == bHost || isWildcardHost(aHost) || isWildcardHost(bHost)
}

func normalizeListenHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
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
