package trojan

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

type fallback struct {
	config config.TrojanFallbackConfig
	slots  chan struct{}
}

func (f *fallback) acquire() bool {
	select {
	case f.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (f *fallback) release() { <-f.slots }

// serveFallback deliberately bypasses Kernel: website visitors have no proxy
// identity, route grant, traffic account or user quota. The backend is fixed by
// configuration, and the slot is held during both classification and relay.
func (s *Service) serveFallback(client, rawClient net.Conn, prefix []byte, probeDeadline time.Time) {
	// Format errors, unknown credentials and incomplete headers share one
	// decision deadline. The authentication lookup is not exposed as a distinct
	// immediate error response or a separate gateway-generated response body.
	if delay := time.Until(probeDeadline); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			return
		}
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.fallback.config.Timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := rawClient.SetDeadline(deadline); err != nil {
		return
	}
	dialer := &net.Dialer{Timeout: s.fallback.config.DialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", s.fallback.config.Addr)
	if err != nil {
		// Do not log probe bytes, credentials, request paths or TLS payload errors.
		s.logger.Debug("Trojan website backend unavailable", zap.String("inbound", s.name))
		return
	}
	defer backend.Close()
	if !s.setUpstream(rawClient, backend) {
		return
	}
	if err := backend.SetDeadline(deadline); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() {
		_ = rawClient.Close()
		_ = backend.Close()
	})
	defer stop()
	s.logger.Debug("Trojan website connection opened", zap.String("inbound", s.name))
	defer s.logger.Debug("Trojan website connection closed", zap.String("inbound", s.name))

	type result struct {
		fromClient bool
		err        error
	}
	results := make(chan result, 2)
	go func() {
		// Replay the consumed prefix exactly once, then copy the unread stream.
		_, err := io.CopyBuffer(backend, io.MultiReader(bytes.NewReader(prefix), client), make([]byte, relayBufferSize))
		if err == nil {
			// An HTTP client may finish writing before receiving a response.
			// Preserve that half-close instead of dropping the backend response.
			if writer, ok := backend.(interface{ CloseWrite() error }); ok {
				err = writer.CloseWrite()
			} else {
				err = io.EOF
			}
		}
		results <- result{fromClient: true, err: err}
	}()
	go func() {
		_, err := io.CopyBuffer(client, backend, make([]byte, relayBufferSize))
		results <- result{err: err}
	}()
	first := <-results
	if first.fromClient && first.err == nil {
		// The connection deadline and shutdown cancellation bound this wait.
		<-results
	} else {
		_ = rawClient.Close()
		_ = backend.Close()
		<-results
	}
}
