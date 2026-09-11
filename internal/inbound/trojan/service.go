package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

const (
	defaultHandshakeTimeout      = 10 * time.Second
	defaultMaxPendingConnections = 256
	defaultUDPIdleTimeout        = 60 * time.Second
	initialAcceptBackoff         = 5 * time.Millisecond
	maximumAcceptBackoff         = time.Second
	relayBufferSize              = 32 * 1024
	packetReadBufferSize         = 4 * 1024
)

// errTrafficRejected ends an association when account policy refuses a payload.
// The refused chunk or datagram is never forwarded.
var errTrafficRejected = errors.New("traffic policy rejected payload")

// errAssociationIdle ends an association that saw no datagram in either
// direction within the configured idle bound.
var errAssociationIdle = errors.New("Trojan UDP association idle")

// Service owns one Trojan TCP/TLS listener. It deliberately exposes only the
// inbound lifecycle; authenticated proxy traffic uses Kernel. Optional anonymous
// website connections use a separate, bounded relay.
type Service struct {
	name             string
	listener         net.Listener
	tlsConfig        *tls.Config
	kernel           *policy.Kernel
	handshakeTimeout time.Duration
	udpIdleTimeout   time.Duration
	pending          chan struct{}
	fallback         *fallback
	logger           *zap.Logger
	ctx              context.Context
	cancel           context.CancelFunc
	connectionsMu    sync.Mutex
	connections      map[net.Conn]io.Closer
	handlers         sync.WaitGroup
	started          atomic.Bool
	closed           atomic.Bool
	closeOnce        sync.Once
	closeErr         error
}

func NewService(inbound config.Inbound, certificate tls.Certificate, kernel *policy.Kernel, logger *zap.Logger) (*Service, error) {
	if kernel == nil {
		return nil, fmt.Errorf("Trojan inbound %s requires a policy kernel", inbound.Name)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	options := inbound.Trojan
	handshakeTimeout := defaultHandshakeTimeout
	maxPending := defaultMaxPendingConnections
	udpIdleTimeout := defaultUDPIdleTimeout
	var website *fallback
	if options != nil {
		if options.HandshakeTimeout != 0 {
			handshakeTimeout = options.HandshakeTimeout
		}
		if options.MaxPendingConnections != 0 {
			maxPending = options.MaxPendingConnections
		}
		if options.UDPIdleTimeout != 0 {
			udpIdleTimeout = options.UDPIdleTimeout
		}
		if options.Fallback != nil {
			configured, err := options.Fallback.WithDefaults()
			if err != nil {
				return nil, fmt.Errorf("Trojan inbound %s: %w", inbound.Name, err)
			}
			website = &fallback{config: configured, slots: make(chan struct{}, configured.MaxConnections)}
		}
	}
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("inbound %s listen: %w", inbound.Name, err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	if website != nil {
		// The fixed backend receives plaintext HTTP/1.1, never HTTP/2 frames.
		tlsConfig.NextProtos = []string{"http/1.1"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		name: inbound.Name, listener: listener,
		tlsConfig: tlsConfig,
		kernel:    kernel, handshakeTimeout: handshakeTimeout, udpIdleTimeout: udpIdleTimeout,
		pending: make(chan struct{}, maxPending), fallback: website,
		logger: logger, ctx: ctx, cancel: cancel, connections: make(map[net.Conn]io.Closer),
	}, nil
}

func (s *Service) Name() string { return s.name }

// Addr returns the bound TCP address for diagnostics and integration tests.
func (s *Service) Addr() net.Addr { return s.listener.Addr() }

func (s *Service) Serve() error {
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("Trojan inbound %s is already serving", s.name)
	}
	var backoff time.Duration
	for {
		client, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				if backoff == 0 {
					backoff = initialAcceptBackoff
				} else {
					backoff *= 2
					if backoff > maximumAcceptBackoff {
						backoff = maximumAcceptBackoff
					}
				}
				timer := time.NewTimer(backoff)
				select {
				case <-timer.C:
					continue
				case <-s.ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return nil
				}
			}
			return fmt.Errorf("accept Trojan TCP connection: %w", err)
		}
		backoff = 0
		select {
		case s.pending <- struct{}{}:
		default:
			_ = client.Close()
			continue
		}
		s.connectionsMu.Lock()
		if s.closed.Load() {
			s.connectionsMu.Unlock()
			<-s.pending
			_ = client.Close()
			continue
		}
		s.connections[client] = nil
		s.handlers.Add(1)
		s.connectionsMu.Unlock()
		go s.handle(client)
	}
}

func (s *Service) handle(rawClient net.Conn) {
	defer s.handlers.Done()
	pending := true
	defer func() {
		if pending {
			<-s.pending
		}
		s.connectionsMu.Lock()
		delete(s.connections, rawClient)
		s.connectionsMu.Unlock()
		_ = rawClient.Close()
	}()

	deadline := time.Now().Add(s.handshakeTimeout)
	if err := rawClient.SetDeadline(deadline); err != nil {
		return
	}
	client := tls.Server(rawClient, s.tlsConfig)
	handshakeCtx, cancel := context.WithDeadline(s.ctx, deadline)
	err := client.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return
	}
	var prefix bytes.Buffer
	var reader io.Reader = client
	probeDeadline := deadline
	if s.fallback != nil {
		probeDeadline = time.Now().Add(s.fallback.config.ProbeTimeout)
		if deadline.Before(probeDeadline) {
			probeDeadline = deadline
		}
		if err := rawClient.SetReadDeadline(probeDeadline); err != nil {
			return
		}
		// ReadCredential consumes at most 58 bytes. Preserve partial reads too,
		// including data returned before EOF or the probe deadline.
		reader = io.TeeReader(io.LimitReader(client, credentialLength+2), &prefix)
	}
	credential, err := ReadCredential(reader)
	var session *policy.Session
	var authenticated bool
	if err == nil {
		session, authenticated = s.kernel.AuthenticateTrojan(s.name, rawClient.RemoteAddr(), credential)
	}
	if !authenticated {
		if s.fallback != nil && s.fallback.acquire() {
			defer s.fallback.release()
			<-s.pending
			pending = false
			s.serveFallback(client, rawClient, prefix.Bytes(), probeDeadline)
		} else if s.fallback != nil {
			s.logger.Debug("Trojan website connection limit reached", zap.String("inbound", s.name))
		}
		return
	}
	// A valid credential retains the original full handshake/request budget.
	// Invalid commands from an authenticated client are never sent to the website.
	if err := rawClient.SetReadDeadline(deadline); err != nil {
		return
	}
	request, err := ReadRequest(client)
	if err != nil {
		return
	}
	if err := rawClient.SetDeadline(time.Time{}); err != nil {
		return
	}
	<-s.pending
	pending = false

	if request.UDPAssociate() {
		s.serveUDPAssociation(client, rawClient, session, request.Target)
		return
	}
	s.serveTCPRequest(client, rawClient, session, request.Target)
}

func (s *Service) serveTCPRequest(client, rawClient net.Conn, session *policy.Session, target string) {
	targetConn, err := s.kernel.OpenTCP(s.ctx, session, target)
	if err != nil {
		s.logger.Debug("Trojan target dial failed", zap.String("inbound", s.name), zap.String("target", target), zap.Error(err))
		return
	}
	if !s.setUpstream(rawClient, targetConn) {
		_ = targetConn.Close()
		return
	}
	defer targetConn.Close()

	stop := s.startRequest(session, rawClient, "TCP", target)
	defer stop()
	if err := relayMetered(s.ctx, client, targetConn, session, s.kernel); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		s.logger.Debug("Trojan relay stopped", zap.String("inbound", s.name), zap.String("target", target), zap.Error(err))
	}
}

// serveUDPAssociation owns one Trojan UDP association. Every datagram carries
// its own destination, so the request header target is only nominal and each
// packet passes through account policy before it is forwarded.
func (s *Service) serveUDPAssociation(client, rawClient net.Conn, session *policy.Session, nominalTarget string) {
	association, err := s.kernel.OpenUDP(s.ctx, session, nominalTarget)
	if err != nil {
		s.logger.Debug("Trojan UDP association failed", zap.String("inbound", s.name), zap.Error(err))
		return
	}
	if !s.setUpstream(rawClient, association) {
		_ = association.Close()
		return
	}
	defer association.Close()

	stop := s.startRequest(session, rawClient, "UDP", nominalTarget)
	defer stop()
	if err := relayUDPMetered(s.ctx, client, association, session, s.kernel, s.udpIdleTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		s.logger.Debug("Trojan UDP association stopped", zap.String("inbound", s.name), zap.Error(err))
	}
}

// startRequest publishes the online and request state once and returns the
// matching single cleanup for every exit path.
func (s *Service) startRequest(session *policy.Session, rawClient net.Conn, protocol, target string) func() {
	s.kernel.Connected(session, rawClient.RemoteAddr(), 0)
	s.kernel.Online(session, true)
	s.kernel.StartRequest(session, 1, protocol, target)
	return func() {
		s.kernel.StopRequest(session, 1)
		s.kernel.Online(session, false)
		s.kernel.Disconnected(session, nil)
	}
}

func (s *Service) setUpstream(client net.Conn, upstream io.Closer) bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	if _, ok := s.connections[client]; !ok || s.closed.Load() {
		return false
	}
	s.connections[client] = upstream
	return true
}

func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
		s.connectionsMu.Lock()
		connections := make([]io.Closer, 0, len(s.connections)*2)
		for client, upstream := range s.connections {
			connections = append(connections, client)
			if upstream != nil {
				connections = append(connections, upstream)
			}
		}
		s.connectionsMu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		s.handlers.Wait()
	})
	return s.closeErr
}

func (s *Service) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() { s.handlers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func relayMetered(parent context.Context, client, target net.Conn, session *policy.Session, kernel *policy.Kernel) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			cancel()
			_ = client.Close()
			_ = target.Close()
		})
	}
	go func() {
		results <- copyMetered(target, client, func(n uint64) bool { return kernel.Admit(ctx, session, n, 0) })
	}()
	go func() {
		results <- copyMetered(client, target, func(n uint64) bool { return kernel.Admit(ctx, session, 0, n) })
	}()
	first := <-results
	closeBoth()
	second := <-results
	if first != nil {
		return first
	}
	return second
}

// relayUDPMetered moves datagrams between one Trojan association and one
// outbound UDP flow. Both directions charge account policy before the payload
// leaves the Gateway, and either an idle association or a policy rejection ends
// the whole association.
func relayUDPMetered(parent context.Context, client net.Conn, association outbound.UDPConn, session *policy.Session, kernel *policy.Kernel, idleTimeout time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var closeOnce sync.Once
	var idle atomic.Bool
	closeBoth := func() {
		closeOnce.Do(func() {
			cancel()
			_ = client.Close()
			_ = association.Close()
		})
	}
	activity := &atomic.Int64{}
	activity.Store(time.Now().UnixNano())
	watchdog := make(chan struct{})
	go func() {
		defer close(watchdog)
		if watchIdle(ctx, idleTimeout, activity) {
			idle.Store(true)
			closeBoth()
		}
	}()
	results := make(chan error, 2)
	go func() {
		results <- copyClientPackets(ctx, client, association, session, kernel, activity)
	}()
	go func() {
		results <- copyAssociationPackets(ctx, client, association, session, kernel, activity)
	}()
	first := <-results
	closeBoth()
	second := <-results
	<-watchdog
	if idle.Load() {
		return errAssociationIdle
	}
	if first != nil {
		return first
	}
	return second
}

// watchIdle reports whether the association exceeded its idle bound. It returns
// false as soon as the association context is done.
func watchIdle(ctx context.Context, timeout time.Duration, activity *atomic.Int64) bool {
	if timeout <= 0 {
		<-ctx.Done()
		return false
	}
	interval := timeout / 2
	if interval <= 0 {
		interval = timeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case now := <-ticker.C:
			if now.UnixNano()-activity.Load() >= int64(timeout) {
				return true
			}
		}
	}
}

func copyClientPackets(ctx context.Context, client io.Reader, association outbound.UDPConn, session *policy.Session, kernel *policy.Kernel, activity *atomic.Int64) error {
	reader := bufio.NewReaderSize(client, packetReadBufferSize)
	buffer := make([]byte, MaxUDPPayloadSize)
	for {
		target, read, err := ReadPacket(reader, buffer)
		if err != nil {
			return err
		}
		activity.Store(time.Now().UnixNano())
		if !kernel.Admit(ctx, session, uint64(read), 0) {
			return errTrafficRejected
		}
		if _, err := association.WriteTo(buffer[:read], target); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A single unroutable or oversized datagram is not an association
			// failure. A closed outbound flow is.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
	}
}

func copyAssociationPackets(ctx context.Context, client io.Writer, association outbound.UDPConn, session *policy.Session, kernel *policy.Kernel, activity *atomic.Int64) error {
	buffer := make([]byte, MaxUDPPayloadSize)
	packet := make([]byte, 0, MaxUDPPayloadSize+maxPacketHeaderSize)
	for {
		read, source, err := association.ReadFrom(buffer)
		if err != nil {
			return err
		}
		activity.Store(time.Now().UnixNano())
		if !kernel.Admit(ctx, session, 0, uint64(read)) {
			return errTrafficRejected
		}
		packet, err = AppendPacket(packet[:0], source, buffer[:read])
		if err != nil {
			continue
		}
		if _, err := client.Write(packet); err != nil {
			return err
		}
	}
}

func copyMetered(destination io.Writer, source io.Reader, admit func(uint64) bool) error {
	buffer := make([]byte, relayBufferSize)
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			if !admit(uint64(read)) {
				return errTrafficRejected
			}
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}
