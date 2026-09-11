package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	Hysteria2InboundType = "hysteria2"
	TrojanInboundType    = "trojan"
)

// InboundConfig is the strict runtime configuration schema.
type InboundConfig struct {
	Inbounds             []Inbound         `yaml:"inbounds"`
	TLS                  TLSConfig         `yaml:"tls"`
	Admin                AdminConfig       `yaml:"admin,omitempty"`
	Sub                  *InboundSubConfig `yaml:"sub,omitempty"`
	DBPath               string            `yaml:"dbPath,omitempty"`
	TrafficFlushInterval time.Duration     `yaml:"trafficFlushInterval,omitempty"`
	Timezone             string            `yaml:"timezone,omitempty"`
	Systemd              *SystemdConfig    `yaml:"systemd,omitempty"`
}

// Inbound is a named protocol listener.
type Inbound struct {
	Name       string                   `yaml:"name"`
	Type       string                   `yaml:"type"`
	Listen     string                   `yaml:"listen"`
	QUIC       *QUICConfig              `yaml:"quic,omitempty"`
	Trojan     *TrojanInboundConfig     `yaml:"trojan,omitempty"`
	Masquerade *InboundMasqueradeConfig `yaml:"masquerade,omitempty"`
}

// InboundMasqueradeConfig decides what an unauthenticated HTTP/3 probe of a
// Hysteria2 inbound sees. Without it the inbound answers 404 for everything.
type InboundMasqueradeConfig struct {
	Type  string                 `yaml:"type"`
	Proxy *MasqueradeProxyConfig `yaml:"proxy,omitempty"`
}

// MasqueradeProxyConfig forwards probe requests to one fixed web backend. The
// URL is never derived from request content, so the inbound cannot be used as
// an open proxy.
type MasqueradeProxyConfig struct {
	URL string `yaml:"url"`
	// RewriteHost sends the backend its own hostname instead of the Host the
	// probe used. Enable it when the backend selects a virtual host by Host.
	RewriteHost bool `yaml:"rewriteHost,omitempty"`
}

// TrojanInboundConfig controls resource limits for a Trojan TCP/TLS inbound.
type TrojanInboundConfig struct {
	HandshakeTimeout      time.Duration `yaml:"handshakeTimeout,omitempty"`
	MaxPendingConnections int           `yaml:"maxPendingConnections,omitempty"`
	// UDPIdleTimeout reclaims a UDP association that saw no datagram in either
	// direction. It is not a TCP CONNECT idle timeout.
	UDPIdleTimeout time.Duration `yaml:"udpIdleTimeout,omitempty"`
	// Fallback serves unauthenticated TLS connections through a fixed HTTP/1.1 backend.
	Fallback *TrojanFallbackConfig `yaml:"fallback,omitempty"`
}

// SubscriptionEndpoint publishes the client-facing address of a named inbound.
// Its address is explicit because a listener may sit behind NAT or a proxy.
type SubscriptionEndpoint struct {
	Inbound    string `yaml:"inbound"`
	ServerAddr string `yaml:"serverAddr"`
	SNI        string `yaml:"sni,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"`
}

// InboundSubConfig publishes one or more named inbounds in a subscription.
// Legacy secrets deliberately have no field here.
type InboundSubConfig struct {
	Listen    string `yaml:"listen,omitempty"`
	PublicURL string `yaml:"publicURL,omitempty"`
	// A pointer distinguishes absent single-endpoint fields from explicitly
	// configured defaults such as insecure: false when checking mixed syntax.
	*SubscriptionEndpoint `yaml:",inline"`
	// Endpoints replaces the single-inbound fields when several listeners
	// should be available through the same subscription URL.
	Endpoints []SubscriptionEndpoint `yaml:"endpoints,omitempty"`
}

// ParseInboundConfig strictly parses and validates the runtime inbound schema.
// It does not read certificates, open databases, resolve DNS, or bind ports.
func ParseInboundConfig(data []byte) (*InboundConfig, error) {
	var cfg InboundConfig
	if err := decodeStrictSingleDocument(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid inbound config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid inbound config: %w", err)
	}
	return &cfg, nil
}

func (c *InboundConfig) validate() error {
	if len(c.Inbounds) == 0 {
		return fmt.Errorf("inbounds must contain at least one item")
	}

	names := make(map[string]string, len(c.Inbounds))
	udpListeners := make([]namedListener, 0, len(c.Inbounds))
	tcpListeners := make([]namedListener, 0, len(c.Inbounds)+2)
	for i := range c.Inbounds {
		inbound := &c.Inbounds[i]
		path := fmt.Sprintf("inbounds[%d]", i)
		if inbound.Name == "" || strings.TrimSpace(inbound.Name) != inbound.Name {
			return fmt.Errorf("%s.name must be non-empty and have no surrounding whitespace", path)
		}
		if previous, exists := names[inbound.Name]; exists {
			return fmt.Errorf("%s.name duplicates %s.name", path, previous)
		}
		names[inbound.Name] = path
		if inbound.Type != Hysteria2InboundType && inbound.Type != TrojanInboundType {
			return fmt.Errorf("%s.type has unsupported value %q", path, inbound.Type)
		}
		listener, err := parseListener(path+".listen", inbound.Listen)
		if err != nil {
			return err
		}
		if inbound.Masquerade != nil {
			if inbound.Type != Hysteria2InboundType {
				return fmt.Errorf("%s.masquerade is only valid for a hysteria2 inbound", path)
			}
			if err := validateInboundMasquerade(path+".masquerade", inbound.Masquerade); err != nil {
				return err
			}
		}
		if inbound.Type == Hysteria2InboundType {
			if inbound.Trojan != nil {
				return fmt.Errorf("%s.trojan is only valid for a trojan inbound", path)
			}
			for _, existing := range udpListeners {
				if listenersDefinitelyConflict(existing.listener, listener) {
					return fmt.Errorf("%s.listen conflicts with %s.listen", path, existing.name)
				}
			}
			udpListeners = append(udpListeners, namedListener{name: path, listener: listener})
			if inbound.QUIC != nil {
				if err := validateInboundQUIC(path+".quic", inbound.QUIC); err != nil {
					return err
				}
			}
		} else {
			if inbound.QUIC != nil {
				return fmt.Errorf("%s.quic is only valid for a hysteria2 inbound", path)
			}
			if inbound.Trojan != nil {
				if err := validateTrojanInbound(path+".trojan", inbound.Trojan); err != nil {
					return err
				}
			}
			for _, existing := range tcpListeners {
				if listenersDefinitelyConflict(existing.listener, listener) {
					return fmt.Errorf("%s.listen conflicts with %s.listen", path, existing.name)
				}
			}
			tcpListeners = append(tcpListeners, namedListener{name: path, listener: listener})
		}
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
	if c.TrafficFlushInterval < 0 {
		return fmt.Errorf("trafficFlushInterval must not be negative")
	}
	if c.TrafficFlushInterval == 0 {
		c.TrafficFlushInterval = 10 * time.Second
	}
	if c.DBPath == "" {
		c.DBPath = "proxy-gateway.db"
	}
	if c.Systemd != nil && c.Systemd.Unit == "" {
		c.Systemd.Unit = "proxy-gateway.service"
	}

	if c.Admin.Listen != "" {
		listener, err := parseListener("admin.listen", c.Admin.Listen)
		if err != nil {
			return err
		}
		if !listener.isLoopback() {
			return fmt.Errorf("admin.listen must use a loopback address")
		}
		tcpListeners = append(tcpListeners, namedListener{name: "admin", listener: listener})
	}
	if c.Sub != nil {
		if c.Sub.Endpoints != nil {
			if len(c.Sub.Endpoints) == 0 {
				return fmt.Errorf("sub.endpoints must contain at least one item")
			}
			if c.Sub.SubscriptionEndpoint != nil {
				return fmt.Errorf("sub.endpoints cannot be combined with sub.inbound, sub.serverAddr, sub.sni or sub.insecure")
			}
			seen := make(map[string]bool, len(c.Sub.Endpoints))
			for i, endpoint := range c.Sub.Endpoints {
				path := fmt.Sprintf("sub.endpoints[%d]", i)
				if err := validateSubscriptionEndpoint(path, endpoint, names); err != nil {
					return err
				}
				if seen[endpoint.Inbound] {
					return fmt.Errorf("%s.inbound duplicates subscription inbound %q", path, endpoint.Inbound)
				}
				seen[endpoint.Inbound] = true
			}
		} else {
			endpoint := SubscriptionEndpoint{}
			if c.Sub.SubscriptionEndpoint != nil {
				endpoint = *c.Sub.SubscriptionEndpoint
			}
			if err := validateSubscriptionEndpoint("sub", endpoint, names); err != nil {
				return err
			}
		}
		if c.Sub.Listen != "" {
			listener, err := parseListener("sub.listen", c.Sub.Listen)
			if err != nil {
				return err
			}
			for _, existing := range tcpListeners {
				if listenersDefinitelyConflict(existing.listener, listener) {
					return fmt.Errorf("sub.listen conflicts with %s.listen", existing.name)
				}
			}
			tcpListeners = append(tcpListeners, namedListener{name: "sub", listener: listener})
		}
	}
	return nil
}

func validateSubscriptionEndpoint(path string, endpoint SubscriptionEndpoint, inbounds map[string]string) error {
	if endpoint.Inbound == "" {
		return fmt.Errorf("%s.inbound must be configured", path)
	}
	if _, exists := inbounds[endpoint.Inbound]; !exists {
		return fmt.Errorf("%s.inbound references unknown inbound %q", path, endpoint.Inbound)
	}
	if endpoint.ServerAddr == "" {
		return fmt.Errorf("%s.serverAddr must be configured", path)
	}
	address, err := parseListener(path+".serverAddr", endpoint.ServerAddr)
	if err != nil {
		return err
	}
	if address.wildcard {
		return fmt.Errorf("%s.serverAddr must name a client-reachable host", path)
	}
	return nil
}

func validateTrojanInbound(path string, trojan *TrojanInboundConfig) error {
	if trojan.Fallback != nil {
		if _, err := trojan.Fallback.WithDefaults(); err != nil {
			return fmt.Errorf("%s.%w", path, err)
		}
	}
	if trojan.HandshakeTimeout < 0 {
		return fmt.Errorf("%s.handshakeTimeout must not be negative", path)
	}
	if trojan.HandshakeTimeout != 0 && (trojan.HandshakeTimeout < time.Second || trojan.HandshakeTimeout > 2*time.Minute) {
		return fmt.Errorf("%s.handshakeTimeout must be between 1s and 2m when configured", path)
	}
	if trojan.MaxPendingConnections < 0 || trojan.MaxPendingConnections > 65535 {
		return fmt.Errorf("%s.maxPendingConnections must be between 1 and 65535 when configured", path)
	}
	if trojan.UDPIdleTimeout < 0 {
		return fmt.Errorf("%s.udpIdleTimeout must not be negative", path)
	}
	if trojan.UDPIdleTimeout != 0 && (trojan.UDPIdleTimeout < 5*time.Second || trojan.UDPIdleTimeout > 30*time.Minute) {
		return fmt.Errorf("%s.udpIdleTimeout must be between 5s and 30m when configured", path)
	}
	return nil
}

// MasqueradeProxyType is the only masquerade mode the data plane implements.
const MasqueradeProxyType = "proxy"

func validateInboundMasquerade(path string, masquerade *InboundMasqueradeConfig) error {
	if masquerade.Type != MasqueradeProxyType {
		return fmt.Errorf("%s.type has unsupported value %q; only %q is implemented", path, masquerade.Type, MasqueradeProxyType)
	}
	if masquerade.Proxy == nil || masquerade.Proxy.URL == "" {
		return fmt.Errorf("%s.proxy.url must be configured", path)
	}
	target, err := url.Parse(masquerade.Proxy.URL)
	if err != nil {
		return fmt.Errorf("%s.proxy.url is invalid: %w", path, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("%s.proxy.url must use http or https", path)
	}
	if target.Host == "" {
		return fmt.Errorf("%s.proxy.url must name a backend host", path)
	}
	if target.User != nil {
		return fmt.Errorf("%s.proxy.url must not embed credentials", path)
	}
	if target.RawQuery != "" || target.Fragment != "" {
		return fmt.Errorf("%s.proxy.url must not carry a query or fragment", path)
	}
	return nil
}

func validateInboundQUIC(path string, quic *QUICConfig) error {
	windows := []struct {
		name  string
		value uint64
	}{
		{name: "initStreamReceiveWindow", value: quic.InitStreamReceiveWindow},
		{name: "maxStreamReceiveWindow", value: quic.MaxStreamReceiveWindow},
		{name: "initConnReceiveWindow", value: quic.InitConnReceiveWindow},
		{name: "maxConnReceiveWindow", value: quic.MaxConnReceiveWindow},
	}
	for _, window := range windows {
		if window.value != 0 && window.value < 16384 {
			return fmt.Errorf("%s.%s must be at least 16384 when configured", path, window.name)
		}
	}
	if quic.MaxIdleTimeout != 0 && (quic.MaxIdleTimeout < 4*time.Second || quic.MaxIdleTimeout > 120*time.Second) {
		return fmt.Errorf("%s.maxIdleTimeout must be between 4s and 120s when configured", path)
	}
	if quic.MaxIncomingStreams != 0 && quic.MaxIncomingStreams < 8 {
		return fmt.Errorf("%s.maxIncomingStreams must be at least 8 when configured", path)
	}
	return nil
}

type listenerAddress struct {
	host     string
	port     uint16
	wildcard bool
	family   int
}

type namedListener struct {
	name     string
	listener listenerAddress
}

func parseListener(path, value string) (listenerAddress, error) {
	if value == "" {
		return listenerAddress{}, fmt.Errorf("%s must be configured", path)
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return listenerAddress{}, fmt.Errorf("%s is invalid: %w", path, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return listenerAddress{}, fmt.Errorf("%s must use a port between 1 and 65535", path)
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	family := 0
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		normalizedHost = ip.String()
		family = 6
		if ip.To4() != nil {
			family = 4
		}
	}
	wildcard := normalizedHost == "" || normalizedHost == "0.0.0.0" || normalizedHost == "::"
	return listenerAddress{host: normalizedHost, port: uint16(port), wildcard: wildcard, family: family}, nil
}

func listenersDefinitelyConflict(a, b listenerAddress) bool {
	if a.port != b.port {
		return false
	}
	if a.host == b.host {
		return true
	}
	if a.host == "" || b.host == "" {
		return true
	}
	return (a.wildcard || b.wildcard) && a.family != 0 && a.family == b.family
}

func (a listenerAddress) isLoopback() bool {
	if a.host == "localhost" {
		return true
	}
	ip := net.ParseIP(a.host)
	return ip != nil && ip.IsLoopback()
}

func decodeStrictSingleDocument(data []byte, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if err == io.EOF {
			return fmt.Errorf("configuration is empty")
		}
		return fmt.Errorf("failed to parse YAML: %w", err)
	}
	if len(root.Content) == 0 {
		return fmt.Errorf("configuration is empty")
	}
	if err := rejectDuplicateKeys(&root, "$"); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return fmt.Errorf("failed to parse trailing YAML: %w", err)
		}
		return fmt.Errorf("multiple YAML documents are not allowed")
	}

	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(out); err != nil {
		return fmt.Errorf("failed strict schema decode: %w", err)
	}
	return nil
}

func rejectDuplicateKeys(node *yaml.Node, path string) error {
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return rejectDuplicateKeys(node.Content[0], path)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]*yaml.Node, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind == yaml.ScalarNode {
				if previous, exists := seen[key.Value]; exists {
					return fmt.Errorf("duplicate key %q at line %d (previously at line %d)", key.Value, key.Line, previous.Line)
				}
				seen[key.Value] = key
			}
			if err := rejectDuplicateKeys(value, path+"."+key.Value); err != nil {
				return err
			}
		}
		return nil
	}
	if node.Kind == yaml.SequenceNode {
		for i, child := range node.Content {
			if err := rejectDuplicateKeys(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
