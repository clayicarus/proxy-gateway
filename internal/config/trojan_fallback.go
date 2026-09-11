package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// TrojanFallbackConfig describes a fixed plaintext HTTP/1.1 backend. TLS is
// terminated by the Trojan listener, which advertises http/1.1 when enabled.
type TrojanFallbackConfig struct {
	Addr           string        `yaml:"addr"`
	ProbeTimeout   time.Duration `yaml:"probeTimeout,omitempty"`
	DialTimeout    time.Duration `yaml:"dialTimeout,omitempty"`
	Timeout        time.Duration `yaml:"timeout,omitempty"`
	MaxConnections int           `yaml:"maxConnections,omitempty"`
}

// WithDefaults validates an independent copy for both the YAML loader and
// programmatic listener construction. It does not resolve or contact the backend.
func (c TrojanFallbackConfig) WithDefaults() (TrojanFallbackConfig, error) {
	address, err := parseListener("fallback.addr", c.Addr)
	if err != nil {
		return c, err
	}
	host, _, _ := net.SplitHostPort(c.Addr)
	if address.wildcard || strings.ContainsAny(host, " /\\?#@\t\r\n") {
		return c, fmt.Errorf("fallback.addr must name a fixed backend host and port")
	}
	if c.ProbeTimeout == 0 {
		c.ProbeTimeout = time.Second
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 3 * time.Second
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 32
	}
	if c.ProbeTimeout < 50*time.Millisecond || c.ProbeTimeout > 10*time.Second {
		return c, fmt.Errorf("fallback.probeTimeout must be between 50ms and 10s")
	}
	if c.DialTimeout < 50*time.Millisecond || c.DialTimeout > 30*time.Second {
		return c, fmt.Errorf("fallback.dialTimeout must be between 50ms and 30s")
	}
	if c.Timeout < time.Second || c.Timeout > 10*time.Minute {
		return c, fmt.Errorf("fallback.timeout must be between 1s and 10m")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 65535 {
		return c, fmt.Errorf("fallback.maxConnections must be between 1 and 65535")
	}
	return c, nil
}
