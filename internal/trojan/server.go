package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

const (
	defaultHandshakeTimeout      = 10 * time.Second
	defaultMaxPendingConnections = 256
	initialAcceptBackoff         = 5 * time.Millisecond
	maximumAcceptBackoff         = time.Second
	relayBufferSize              = 32 * 1024
)

var (
	ErrTrafficRejected = errors.New("traffic policy rejected payload")
	ErrAlreadyServing  = errors.New("Trojan server is already serving")
)

// OutboundRouter resolves the explicitly selected outbound from username:node.
type OutboundRouter interface {
	GetOutboundForID(id string) (hyServer.Outbound, error)
}

// TrafficLogger is the subset shared by Hysteria2 and Trojan relays.
type TrafficLogger interface {
	LogTraffic(id string, tx, rx uint64) bool
	LogOnlineState(id string, online bool)
}

// ConnectionTracker records process-local connection and request state.
type ConnectionTracker interface {
	Connect(addr net.Addr, id string)
	Disconnect(addr net.Addr)
	StartTCP(addr net.Addr, target string)
	StopTCP(addr net.Addr, target string)
}

// ServerConfig contains the dependencies and resource bounds for a Trojan
// TCP CONNECT listener.
type ServerConfig struct {
	Listen                string
	TLSConfig             *tls.Config
	Authenticator         *Authenticator
	Outbound              OutboundRouter
	TrafficLogger         TrafficLogger
	ConnectionTracker     ConnectionTracker
	HandshakeTimeout      time.Duration
	MaxPendingConnections int
	Logger                *zap.Logger
}

type trackedConnection struct {
	client net.Conn
	target net.Conn
}

// Server accepts standard Trojan TCP CONNECT requests over TLS.
type Server struct {
	listener          net.Listener
	tlsConfig         *tls.Config
	authenticator     *Authenticator
	outbound          OutboundRouter
	trafficLogger     TrafficLogger
	connectionTracker ConnectionTracker
	handshakeTimeout  time.Duration
	pending           chan struct{}
	logger            *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc

	connectionsMu sync.Mutex
	connections   map[net.Conn]*trackedConnection
	handlers      sync.WaitGroup

	serveStarted atomic.Bool
	serveDone    chan struct{}
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

// NewServer validates its dependencies and synchronously binds the TCP
// listener. A bind failure is therefore a startup failure, not a background
// goroutine failure.
func NewServer(config ServerConfig) (*Server, error) {
	if config.Listen == "" {
		return nil, fmt.Errorf("Trojan listen address is required")
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen for Trojan TCP: %w", err)
	}
	server, err := newServer(listener, config)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return server, nil
}

func newServer(listener net.Listener, config ServerConfig) (*Server, error) {
	if listener == nil {
		return nil, fmt.Errorf("Trojan listener is required")
	}
	if config.TLSConfig == nil || (len(config.TLSConfig.Certificates) == 0 && config.TLSConfig.GetCertificate == nil) {
		return nil, fmt.Errorf("Trojan TLS certificate is required")
	}
	if config.Authenticator == nil {
		return nil, fmt.Errorf("Trojan authenticator is required")
	}
	if config.Outbound == nil {
		return nil, fmt.Errorf("Trojan outbound router is required")
	}
	if config.TrafficLogger == nil {
		return nil, fmt.Errorf("Trojan traffic logger is required")
	}
	if config.ConnectionTracker == nil {
		return nil, fmt.Errorf("Trojan connection tracker is required")
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = defaultHandshakeTimeout
	}
	if config.HandshakeTimeout < 0 {
		return nil, fmt.Errorf("Trojan handshake timeout must be positive")
	}
	if config.MaxPendingConnections == 0 {
		config.MaxPendingConnections = defaultMaxPendingConnections
	}
	if config.MaxPendingConnections < 0 {
		return nil, fmt.Errorf("Trojan maximum pending connections must be positive")
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	tlsConfig := config.TLSConfig.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		listener:          listener,
		tlsConfig:         tlsConfig,
		authenticator:     config.Authenticator,
		outbound:          config.Outbound,
		trafficLogger:     config.TrafficLogger,
		connectionTracker: config.ConnectionTracker,
		handshakeTimeout:  config.HandshakeTimeout,
		pending:           make(chan struct{}, config.MaxPendingConnections),
		logger:            config.Logger,
		ctx:               ctx,
		cancel:            cancel,
		connections:       make(map[net.Conn]*trackedConnection),
		serveDone:         make(chan struct{}),
	}, nil
}

// Addr is the bound TCP listener address.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Serve accepts connections until Close is called or the listener fails.
func (s *Server) Serve() error {
	if !s.serveStarted.CompareAndSwap(false, true) {
		return ErrAlreadyServing
	}
	defer close(s.serveDone)

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
				s.logger.Warn("temporary Trojan accept failure", zap.Duration("retryIn", backoff), zap.Error(err))
				timer := time.NewTimer(backoff)
				select {
				case <-timer.C:
					continue
				case <-s.ctx.Done():
					if !timer.Stop() {
						<-timer.C
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
			s.logger.Debug("Trojan pending connection limit reached", zap.String("addr", client.RemoteAddr().String()))
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
		s.connections[client] = &trackedConnection{client: client}
		s.handlers.Add(1)
		s.connectionsMu.Unlock()
		go s.handle(client)
	}
}

func (s *Server) handle(rawClient net.Conn) {
	defer s.handlers.Done()
	pending := true
	defer func() {
		if pending {
			<-s.pending
		}
		s.removeConnection(rawClient)
		_ = rawClient.Close()
	}()

	deadline := time.Now().Add(s.handshakeTimeout)
	if err := rawClient.SetDeadline(deadline); err != nil {
		s.logger.Debug("failed to set Trojan handshake deadline", zap.String("addr", rawClient.RemoteAddr().String()), zap.Error(err))
		return
	}
	tlsClient := tls.Server(rawClient, s.tlsConfig)
	handshakeCtx, cancel := context.WithDeadline(s.ctx, deadline)
	err := tlsClient.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		s.logger.Debug("Trojan TLS handshake failed", zap.String("addr", rawClient.RemoteAddr().String()), zap.Error(err))
		return
	}

	credential, err := ReadCredential(tlsClient)
	if err != nil {
		s.logger.Debug("Trojan credential header rejected", zap.String("addr", rawClient.RemoteAddr().String()), zap.Error(err))
		return
	}
	id, ok := s.authenticator.Authenticate(credential)
	if !ok {
		s.logger.Debug("Trojan authentication rejected", zap.String("addr", rawClient.RemoteAddr().String()))
		return
	}
	target, err := ReadConnectTarget(tlsClient)
	if err != nil {
		s.logger.Debug("Trojan request rejected", zap.String("addr", rawClient.RemoteAddr().String()), zap.Error(err))
		return
	}
	if err := rawClient.SetDeadline(time.Time{}); err != nil {
		s.logger.Debug("failed to clear Trojan handshake deadline", zap.String("addr", rawClient.RemoteAddr().String()), zap.Error(err))
		return
	}

	<-s.pending
	pending = false

	outbound, err := s.outbound.GetOutboundForID(id)
	if err != nil {
		s.logger.Debug("Trojan route rejected", zap.String("id", id), zap.String("target", target), zap.Error(err))
		return
	}
	var targetConn net.Conn
	if contextual, ok := outbound.(interface {
		TCPContext(context.Context, string) (net.Conn, error)
	}); ok {
		targetConn, err = contextual.TCPContext(s.ctx, target)
	} else {
		targetConn, err = outbound.TCP(target)
	}
	if err != nil {
		s.logger.Debug("Trojan target dial failed", zap.String("id", id), zap.String("target", target), zap.Error(err))
		return
	}
	if !s.setTarget(rawClient, targetConn) {
		_ = targetConn.Close()
		return
	}
	defer targetConn.Close()

	clientAddr := rawClient.RemoteAddr()
	s.trafficLogger.LogOnlineState(id, true)
	s.connectionTracker.Connect(clientAddr, id)
	s.connectionTracker.StartTCP(clientAddr, target)
	defer func() {
		s.connectionTracker.StopTCP(clientAddr, target)
		s.connectionTracker.Disconnect(clientAddr)
		s.trafficLogger.LogOnlineState(id, false)
	}()

	if err := relayMetered(tlsClient, targetConn, id, s.trafficLogger); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, ErrTrafficRejected) {
		s.logger.Debug("Trojan relay stopped", zap.String("id", id), zap.String("target", target), zap.Error(err))
	}
}

func (s *Server) setTarget(client, target net.Conn) bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	tracked := s.connections[client]
	if tracked == nil || s.closed.Load() {
		return false
	}
	tracked.target = target
	return true
}

func (s *Server) removeConnection(client net.Conn) {
	s.connectionsMu.Lock()
	delete(s.connections, client)
	s.connectionsMu.Unlock()
}

// Close stops accept, closes pending and authenticated connections, and waits
// for every connection handler to finish.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
		if s.serveStarted.Load() {
			<-s.serveDone
		}

		s.connectionsMu.Lock()
		connections := make([]*trackedConnection, 0, len(s.connections))
		for _, connection := range s.connections {
			connections = append(connections, connection)
		}
		s.connectionsMu.Unlock()
		for _, connection := range connections {
			_ = connection.client.Close()
			if connection.target != nil {
				_ = connection.target.Close()
			}
		}
		s.handlers.Wait()
	})
	return s.closeErr
}

func relayMetered(client, target net.Conn, id string, logger TrafficLogger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logTraffic := func(tx, rx uint64) bool {
		if contextual, ok := logger.(interface {
			LogTrafficContext(context.Context, string, uint64, uint64) bool
		}); ok {
			return contextual.LogTrafficContext(ctx, id, tx, rx)
		}
		return logger.LogTraffic(id, tx, rx)
	}
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
		results <- copyMetered(target, client, func(n uint64) bool {
			return logTraffic(n, 0)
		})
	}()
	go func() {
		results <- copyMetered(client, target, func(n uint64) bool {
			return logTraffic(0, n)
		})
	}()

	first := <-results
	closeBoth()
	second := <-results
	if first != nil {
		return first
	}
	return second
}

// copyMetered intentionally matches Hysteria2's accounting order: a complete
// read chunk is logged before the corresponding single Write call. A rejected
// chunk is not written; a later short or failed write remains fully counted.
func copyMetered(destination io.Writer, source io.Reader, log func(uint64) bool) error {
	buffer := make([]byte, relayBufferSize)
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			if !log(uint64(read)) {
				return ErrTrafficRejected
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
