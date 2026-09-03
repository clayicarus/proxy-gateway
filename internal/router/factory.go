package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	coreErrors "github.com/apernet/hysteria/core/v2/errors"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

const (
	nodeDNSLookupTimeout = 3 * time.Second
	maxConnectAttempts   = 8
)

type NodeState string

const (
	NodeConnecting  NodeState = "Connecting"
	NodeReady       NodeState = "Ready"
	NodeUnavailable NodeState = "Unavailable"
	NodeBackoff     NodeState = "Backoff"
)

type NodeStatus struct {
	Name         string    `json:"name"`
	State        NodeState `json:"state"`
	ResolvedAddr string    `json:"resolvedAddr,omitempty"`
	LastError    string    `json:"lastError,omitempty"`
	LastSuccess  time.Time `json:"lastSuccess,omitempty"`
	NextRetry    time.Time `json:"nextRetry,omitempty"`
}

type connectedOutbound interface {
	hyServer.Outbound
	Close() error
}

type nodeConnector interface {
	Connect(context.Context, string, *config.Hysteria2OutboundConfig) (connectedOutbound, string, error)
}

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type hysteria2Connector struct {
	resolver ipResolver
	logger   *zap.Logger
	dial     func(*config.Hysteria2OutboundConfig, *net.UDPAddr, string, *zap.Logger) (connectedOutbound, error)
}

func (c *hysteria2Connector) Connect(ctx context.Context, name string, cfg *config.Hysteria2OutboundConfig) (connectedOutbound, string, error) {
	if cfg == nil || cfg.Addr == "" || cfg.Auth == "" {
		return nil, "", fmt.Errorf("node %s requires hysteria2 addr and auth", name)
	}
	addresses, sni, err := c.resolve(ctx, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("node %s resolve %s: %w", name, cfg.Addr, err)
	}
	var attemptErrors []error
	for _, addr := range addresses {
		dial := c.dial
		if dial == nil {
			dial = func(cfg *config.Hysteria2OutboundConfig, addr *net.UDPAddr, sni string, logger *zap.Logger) (connectedOutbound, error) {
				return newHysteria2Outbound(cfg, addr, sni, logger)
			}
		}
		outbound, err := dial(cfg, addr, sni, c.logger)
		if err == nil {
			return outbound, addr.String(), nil
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("%s: %w", addr, err))
		var authErr coreErrors.AuthError
		var configErr coreErrors.ConfigError
		if errors.As(err, &authErr) || errors.As(err, &configErr) {
			break
		}
	}
	return nil, "", fmt.Errorf("node %s connect failed: %w", name, errors.Join(attemptErrors...))
}

func (c *hysteria2Connector) resolve(parent context.Context, cfg *config.Hysteria2OutboundConfig) ([]*net.UDPAddr, string, error) {
	host, rawPort, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, "", err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, "", fmt.Errorf("invalid port %q", rawPort)
	}
	if ip, zone := parseLiteralIP(host); ip != nil {
		sni := cfg.SNI
		if sni == "" {
			sni = ip.String()
		}
		return []*net.UDPAddr{{IP: ip, Port: port, Zone: zone}}, sni, nil
	}
	sni := cfg.SNI
	if sni == "" {
		sni = host
	}
	ctx, cancel := context.WithTimeout(parent, nodeDNSLookupTimeout)
	defer cancel()
	ips, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, "", err
	}
	seen := make(map[string]bool, len(ips))
	addresses := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		addresses = append(addresses, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port})
	}
	if len(addresses) == 0 {
		return nil, "", fmt.Errorf("no A or AAAA records")
	}
	return addresses, sni, nil
}

func parseLiteralIP(host string) (net.IP, string) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, ""
	}
	if index := strings.LastIndexByte(host, '%'); index > 0 {
		if ip := net.ParseIP(host[:index]); ip != nil {
			return ip, host[index+1:]
		}
	}
	return nil, ""
}

type nodeEntry struct {
	name       string
	cfg        *config.Hysteria2OutboundConfig
	connector  nodeConnector
	semaphore  chan struct{}
	retryDelay func(int) time.Duration
	logger     *zap.Logger

	mu           sync.RWMutex
	client       connectedOutbound
	status       NodeStatus
	reconnect    chan struct{}
	firstAttempt chan struct{}
	firstOnce    sync.Once
}

func newNodeEntry(name string, cfg *config.Hysteria2OutboundConfig, connector nodeConnector, semaphore chan struct{}, retryDelay func(int) time.Duration, logger *zap.Logger) *nodeEntry {
	return &nodeEntry{
		name:         name,
		cfg:          cfg,
		connector:    connector,
		semaphore:    semaphore,
		retryDelay:   retryDelay,
		logger:       logger,
		status:       NodeStatus{Name: name, State: NodeConnecting},
		reconnect:    make(chan struct{}, 1),
		firstAttempt: make(chan struct{}),
	}
}

func (e *nodeEntry) run(ctx context.Context) {
	failures := 0
	for {
		if failures > 0 {
			delay := e.retryDelay(failures - 1)
			next := time.Now().Add(delay)
			e.updateStatus(NodeBackoff, "", next)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				e.closeClient()
				return
			case <-timer.C:
			}
		}

		e.updateStatus(NodeConnecting, "", time.Time{})
		select {
		case e.semaphore <- struct{}{}:
		case <-ctx.Done():
			e.closeClient()
			return
		}
		client, resolvedAddr, err := e.connector.Connect(ctx, e.name, e.cfg)
		<-e.semaphore
		e.firstOnce.Do(func() { close(e.firstAttempt) })
		if err != nil {
			failures++
			e.updateStatus(NodeUnavailable, err.Error(), time.Time{})
			e.logger.Warn("hy2 node unavailable", zap.String("node", e.name), zap.Error(err))
			continue
		}

		failures = 0
		e.setReady(client, resolvedAddr)
		select {
		case <-ctx.Done():
			e.closeClient()
			return
		case <-e.reconnect:
			failures = 1
		}
	}
}

func (e *nodeEntry) setReady(client connectedOutbound, resolvedAddr string) {
	now := time.Now().UTC()
	e.mu.Lock()
	old := e.client
	e.client = client
	e.status.State = NodeReady
	e.status.ResolvedAddr = resolvedAddr
	e.status.LastError = ""
	e.status.LastSuccess = now
	e.status.NextRetry = time.Time{}
	e.mu.Unlock()
	if old != nil && old != client {
		_ = old.Close()
	}
	e.logger.Info("hy2 node ready", zap.String("node", e.name), zap.String("resolvedAddr", resolvedAddr))
}

func (e *nodeEntry) updateStatus(state NodeState, lastError string, nextRetry time.Time) {
	e.mu.Lock()
	e.status.State = state
	if lastError != "" {
		e.status.LastError = lastError
	}
	e.status.NextRetry = nextRetry
	e.mu.Unlock()
}

func (e *nodeEntry) currentClient() (connectedOutbound, error) {
	e.mu.RLock()
	client := e.client
	status := e.status
	e.mu.RUnlock()
	if client == nil || status.State != NodeReady {
		if status.LastError != "" {
			return nil, fmt.Errorf("node %s unavailable: %s", e.name, status.LastError)
		}
		return nil, fmt.Errorf("node %s unavailable: %s", e.name, status.State)
	}
	return client, nil
}

func (e *nodeEntry) TCP(reqAddr string) (net.Conn, error) {
	client, err := e.currentClient()
	if err != nil {
		return nil, err
	}
	conn, err := client.TCP(reqAddr)
	if isClosedConnection(err) {
		e.markUnavailable(client, err)
	}
	return conn, err
}

func (e *nodeEntry) UDP(reqAddr string) (hyServer.UDPConn, error) {
	client, err := e.currentClient()
	if err != nil {
		return nil, err
	}
	conn, err := client.UDP(reqAddr)
	if err != nil {
		if isClosedConnection(err) {
			e.markUnavailable(client, err)
		}
		return nil, err
	}
	return &nodeUDPConn{UDPConn: conn, failed: func(err error) { e.markUnavailable(client, err) }}, nil
}

func (e *nodeEntry) markUnavailable(client connectedOutbound, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	if e.client != client {
		e.mu.Unlock()
		return
	}
	e.client = nil
	e.status.State = NodeUnavailable
	e.status.LastError = err.Error()
	e.status.NextRetry = time.Time{}
	e.mu.Unlock()
	_ = client.Close()
	select {
	case e.reconnect <- struct{}{}:
	default:
	}
}

func (e *nodeEntry) closeClient() {
	e.mu.Lock()
	client := e.client
	e.client = nil
	e.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

func (e *nodeEntry) snapshot() NodeStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

func isClosedConnection(err error) bool {
	if err == nil {
		return false
	}
	var closed coreErrors.ClosedError
	return errors.As(err, &closed)
}

type nodeUDPConn struct {
	hyServer.UDPConn
	failed func(error)
}

func (c *nodeUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if isClosedConnection(err) {
		c.failed(err)
	} else if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		c.failed(coreErrors.ClosedError{Err: err})
	}
	return n, addr, err
}

func (c *nodeUDPConn) WriteTo(b []byte, addr string) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	if isClosedConnection(err) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		c.failed(err)
	}
	return n, err
}

type OutboundFactory struct {
	direct    *DirectOutbound
	entries   map[string]*nodeEntry
	ctx       context.Context
	cancel    context.CancelFunc
	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func NewOutboundFactory(nodes map[string]config.NodeConfig, logger *zap.Logger) *OutboundFactory {
	connector := &hysteria2Connector{resolver: net.DefaultResolver, logger: logger}
	return newOutboundFactory(nodes, logger, connector, defaultRetryDelay)
}

func newOutboundFactory(nodes map[string]config.NodeConfig, logger *zap.Logger, connector nodeConnector, retryDelay func(int) time.Duration) *OutboundFactory {
	ctx, cancel := context.WithCancel(context.Background())
	factory := &OutboundFactory{
		direct:  &DirectOutbound{logger: logger},
		entries: make(map[string]*nodeEntry, len(nodes)),
		ctx:     ctx,
		cancel:  cancel,
	}
	semaphore := make(chan struct{}, maxConnectAttempts)
	for name, node := range nodes {
		cfg := node.Hysteria2
		if node.Type != "hysteria2" {
			cfg = nil
		}
		factory.entries[name] = newNodeEntry(name, cfg, connector, semaphore, retryDelay, logger)
	}
	return factory
}

func defaultRetryDelay(failure int) time.Duration {
	if failure < 0 {
		failure = 0
	}
	if failure > 6 {
		failure = 6
	}
	delay := time.Second * time.Duration(1<<failure)
	if delay > time.Minute {
		delay = time.Minute
	}
	jitter := 0.8 + rand.Float64()*0.4
	delay = time.Duration(float64(delay) * jitter)
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func (f *OutboundFactory) Start() {
	f.startOnce.Do(func() {
		for _, entry := range f.entries {
			f.wg.Add(1)
			go func(entry *nodeEntry) {
				defer f.wg.Done()
				entry.run(f.ctx)
			}(entry)
		}
	})
}

func (f *OutboundFactory) Warmup(ctx context.Context) error {
	f.Start()
	var wait sync.WaitGroup
	wait.Add(len(f.entries))
	for _, entry := range f.entries {
		go func(entry *nodeEntry) {
			defer wait.Done()
			select {
			case <-entry.firstAttempt:
			case <-ctx.Done():
			}
		}(entry)
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *OutboundFactory) Get(name string) (hyServer.Outbound, error) {
	if name == "direct" {
		return f.direct, nil
	}
	entry, ok := f.entries[name]
	if !ok {
		return nil, fmt.Errorf("unknown node: %s", name)
	}
	return entry, nil
}

func (f *OutboundFactory) NodeStatuses() map[string]NodeStatus {
	result := make(map[string]NodeStatus, len(f.entries))
	for name, entry := range f.entries {
		result[name] = entry.snapshot()
	}
	return result
}

func (f *OutboundFactory) Close() {
	f.closeOnce.Do(func() {
		f.cancel()
		f.Start()
		f.wg.Wait()
	})
}
