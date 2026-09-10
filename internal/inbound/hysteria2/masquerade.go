package hysteria2

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

const (
	masqueradeDialTimeout           = 10 * time.Second
	masqueradeTLSHandshakeTimeout   = 10 * time.Second
	masqueradeResponseHeaderTimeout = 15 * time.Second
	masqueradeIdleConnTimeout       = 90 * time.Second
	masqueradeMaxIdleConns          = 32
	masqueradeMaxIdleConnsPerHost   = 8
)

// masquerade answers every request that is not a Hysteria2 authentication
// request. It exists so that an active probe of the inbound observes an
// ordinary website instead of a proxy.
type masquerade struct {
	handler   http.Handler
	transport *http.Transport
}

// newMasquerade builds the probe-facing handler for one inbound. A nil config
// yields a nil masquerade, which leaves the upstream 404 behaviour unchanged.
func newMasquerade(cfg *config.InboundMasqueradeConfig, inbound string, logger *zap.Logger) (*masquerade, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Type != config.MasqueradeProxyType || cfg.Proxy == nil {
		return nil, fmt.Errorf("inbound %s masquerade type %q is not implemented", inbound, cfg.Type)
	}
	target, err := url.Parse(cfg.Proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("inbound %s masquerade url: %w", inbound, err)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	rewriteHost := cfg.Proxy.RewriteHost
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: masqueradeDialTimeout}).DialContext,
		TLSHandshakeTimeout:   masqueradeTLSHandshakeTimeout,
		ResponseHeaderTimeout: masqueradeResponseHeaderTimeout,
		IdleConnTimeout:       masqueradeIdleConnTimeout,
		MaxIdleConns:          masqueradeMaxIdleConns,
		MaxIdleConnsPerHost:   masqueradeMaxIdleConnsPerHost,
		ForceAttemptHTTP2:     true,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			originalHost := request.In.Host
			request.SetURL(target)
			if !rewriteHost {
				// SetURL rewrites Host to the backend. Restore the Host the
				// probe used unless the backend needs its own virtual host.
				request.Out.Host = originalHost
			}
			// A plain web server would not report a proxy in front of it, and
			// the probe's address must not reach the backend either.
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			request.Out.Header.Del("Forwarded")
		},
		Transport: transport,
		// Keep upstream failures indistinguishable from an ordinary broken
		// backend: no proxy error text, no gateway identity.
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			logger.Debug("masquerade backend failed", zap.String("inbound", inbound), zap.Error(err))
			writer.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return &masquerade{handler: proxy, transport: transport}, nil
}

// Handler returns the http.Handler to install, or nil when no masquerade is
// configured.
func (m *masquerade) Handler() http.Handler {
	if m == nil {
		return nil
	}
	return m.handler
}

// Close releases pooled backend connections. It is safe on a nil masquerade.
func (m *masquerade) Close() {
	if m == nil {
		return
	}
	m.transport.CloseIdleConnections()
}
