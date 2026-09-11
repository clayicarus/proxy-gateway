package trojan

import (
	"bytes"
	"context"
	"errors"
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

// overCapacityWriteTimeout bounds the only response the gateway writes itself.
const overCapacityWriteTimeout = 5 * time.Second

// overCapacityResponse is the sole gateway-generated response on the website
// path. Closing the connection instead would restore the "TLS succeeds then
// silence" signature that this fallback exists to remove, and slot exhaustion is
// something a probe can cause on demand. It carries no server identity and no
// body, so it does not describe the gateway; a prober that can compare it with
// the origin's own 404 under normal load can still tell them apart.
var overCapacityResponse = []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

func (s *Service) writeOverCapacityResponse(client net.Conn) {
	if err := client.SetWriteDeadline(time.Now().Add(overCapacityWriteTimeout)); err != nil {
		return
	}
	_, _ = client.Write(overCapacityResponse)
}

// serveFallback deliberately bypasses Kernel: website visitors have no proxy
// identity, route grant, traffic account or user quota. The backend is fixed by
// configuration, and the slot is held for the whole relay.
//
// The gateway adds no decision delay of its own. Every classification outcome
// reaches the same fixed backend and the gateway never writes a response, so
// there is no gateway-generated timing signal to equalize: an unknown
// credential, a malformed header and a browser request are all answered by the
// origin. A truncated header still stalls until the probe deadline because the
// header read itself blocks, which is how an ordinary web server behaves while
// it waits for the rest of a request.
func (s *Service) serveFallback(client, rawClient net.Conn, prefix []byte) {
	idle := s.fallback.config.IdleTimeout
	if err := rawClient.SetDeadline(time.Now().Add(idle)); err != nil {
		return
	}
	dialer := &net.Dialer{Timeout: s.fallback.config.DialTimeout}
	backend, err := dialer.DialContext(s.ctx, "tcp", s.fallback.config.Addr)
	if err != nil {
		// Do not log probe bytes, credentials, request paths or TLS payload errors.
		s.logger.Debug("Trojan website backend unavailable", zap.String("inbound", s.name))
		return
	}
	defer backend.Close()
	if !s.setUpstream(rawClient, backend) {
		return
	}
	// The deadline is an idle bound, not a connection lifetime: a transfer in
	// either direction pushes both ends forward, so an active visitor is never
	// interrupted mid-download and only a silent connection is reclaimed.
	extend := func() {
		deadline := time.Now().Add(idle)
		_ = rawClient.SetDeadline(deadline)
		_ = backend.SetDeadline(deadline)
	}
	extend()
	stop := context.AfterFunc(s.ctx, func() {
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
		err := copyRefreshingIdle(backend, io.MultiReader(bytes.NewReader(prefix), client), extend)
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
		results <- result{err: copyRefreshingIdle(client, backend, extend)}
	}()
	first := <-results
	if first.fromClient && first.err == nil {
		// The idle deadline and shutdown cancellation bound this wait.
		<-results
	} else {
		_ = rawClient.Close()
		_ = backend.Close()
		<-results
	}
}

// copyRefreshingIdle copies one direction and pushes the shared idle deadline
// forward around every transfer, so activity keeps the connection alive while
// inactivity lets the deadline close it.
func copyRefreshingIdle(destination io.Writer, source io.Reader, extend func()) error {
	buffer := make([]byte, relayBufferSize)
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			extend()
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
			extend()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}
