package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/api"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/inbound"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	trojanInbound "github.com/clayicarus/proxy-gateway/internal/inbound/trojan"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/systemd"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "record-exit" {
		runRecordExit(os.Args[2:])
		return
	}
	if err := runGateway(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hy2-gateway:", err)
		os.Exit(1)
	}
}

func runGateway(args []string) error {
	return runGatewayContext(context.Background(), args)
}

func runGatewayContext(runCtx context.Context, args []string) error {
	flags := flag.NewFlagSet("proxy-gateway", flag.ExitOnError)
	configPath := flags.String("c", "configs/gateway.yaml", "path to config file")
	_ = flags.Parse(args)

	// Initialize logger
	zapCfg := zap.NewProductionConfig()
	zapCfg.Encoding = "console"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := zapCfg.Build()
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.LoadRuntime(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger.Info("config loaded",
		zap.String("listen", cfg.Listen),
	)

	// Initialize SQLite store
	store, err := storage.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		return fmt.Errorf("open sqlite store: %w", err)
	}
	logger.Info("sqlite store opened", zap.String("path", cfg.DBPath))

	// Load the restart-applied database snapshot. An empty database is valid;
	// the local management Web creates the first users and nodes.
	snapshot, err := store.LoadRuntimeSnapshot(context.Background())
	if err != nil {
		_ = store.Close()
		return fmt.Errorf("load runtime snapshot: %w", err)
	}
	users, nodes := snapshot.Users, snapshot.Nodes
	location, _ := time.LoadLocation(cfg.Timezone)
	logger.Info("runtime configuration loaded", zap.Int("users", len(users)), zap.Int("nodes", len(nodes)))

	// Initialize shared components.
	kernel := policy.New(users, nodes, store, logger, location)

	// Load TLS before acquiring listeners so certificate failure owns no bound
	// sockets. All listeners and protocol servers are then constructed before
	// any serve loop starts.
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		_ = store.Close()
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	type httpService struct {
		name     string
		server   *http.Server
		listener net.Listener
	}
	var httpServices []httpService
	inboundManager := inbound.NewManager()
	cleanupConstructed := func() {
		for _, service := range httpServices {
			_ = service.listener.Close()
		}
		_ = inboundManager.Close()
		kernel.CloseOutbounds()
		_ = store.Close()
	}

	adminListen := cfg.Admin.Listen
	if adminListen != "" {
		if !isLoopbackListen(adminListen) {
			cleanupConstructed()
			return fmt.Errorf("management web must listen on a loopback address: %s", adminListen)
		}
		manager, err := api.NewManager(cfg, store, kernel.Traffic(), logger, kernel.Tracker())
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("create management web: %w", err)
		}
		manager.SetNodeStatusProvider(kernel)
		httpServer := &http.Server{Addr: adminListen, Handler: manager.Handler(), ReadHeaderTimeout: 10 * time.Second}
		listener, err := net.Listen("tcp", adminListen)
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("management web listen %s: %w", adminListen, err)
		}
		httpServices = append(httpServices, httpService{name: "management web", server: httpServer, listener: listener})
	}
	if cfg.Sub != nil && cfg.Sub.Listen != "" {
		httpServer := &http.Server{Addr: cfg.Sub.Listen, Handler: api.NewDatabaseSubscriptionHandler(cfg, store, users, nodes, logger).Handler(), ReadHeaderTimeout: 10 * time.Second}
		listener, err := net.Listen("tcp", cfg.Sub.Listen)
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("subscription service listen %s: %w", cfg.Sub.Listen, err)
		}
		httpServices = append(httpServices, httpService{name: "subscription service", server: httpServer, listener: listener})
	}
	for _, configuredInbound := range cfg.Inbounds {
		var service inbound.Service
		switch configuredInbound.Type {
		case config.Hysteria2InboundType:
			service, err = hyInbound.NewService(configuredInbound, tlsCert, kernel)
		case config.TrojanInboundType:
			service, err = trojanInbound.NewService(configuredInbound, tlsCert, kernel, logger)
		default:
			err = fmt.Errorf("unsupported inbound type %q", configuredInbound.Type)
		}
		if err != nil {
			cleanupConstructed()
			return err
		}
		inboundManager.Add(service)
	}

	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := kernel.Warmup(warmupCtx); err != nil {
		logger.Warn("node warmup incomplete; startup will continue", zap.Error(err))
	}
	warmupCancel()
	kernel.Traffic().StartPeriodicFlush(cfg.TrafficFlushInterval)
	httpErrCh := make(chan error, len(httpServices))
	for _, service := range httpServices {
		go serveHTTP(logger, service.name, service.server, service.listener, httpErrCh)
	}

	// Only user lifecycle fields are hot-reloaded. Node definitions and route
	// authorization remain the startup snapshot and require a full restart.
	userRefreshStop := make(chan struct{})
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		defer background.Done()
		refreshUserState(userRefreshStop, store, kernel, logger)
	}()

	systemdStop := make(chan struct{})

	logger.Info("proxy-gateway starting", zap.Int("inbounds", inboundManager.Len()))
	var gatewayServing atomic.Bool
	gatewayServing.Store(true)
	inboundErrCh := inboundManager.Start()

	if _, err := store.StartProcessRun(os.Getpid(), snapshot.Revision, os.Getenv("HY2_RESTART_TRIGGER")); err != nil {
		logger.Warn("failed to record process start", zap.Error(err))
	}
	if err := store.SetActiveRevision(snapshot.Revision); err != nil {
		logger.Warn("failed to record active config revision", zap.Error(err))
	}
	if cfg.Systemd != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			runRestartScheduler(systemdStop, store, cfg.Systemd.Unit, logger)
		}()
		if cfg.Systemd.Watchdog {
			background.Add(1)
			go func() {
				defer background.Done()
				runWatchdog(systemdStop, store, &gatewayServing, logger)
			}()
		}
	}

	// Wait for shutdown signal or server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var serviceErr error
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case serviceErr = <-httpErrCh:
		logger.Error("service error", zap.Error(serviceErr))
	case serviceErr = <-inboundErrCh:
		logger.Error("service error", zap.Error(serviceErr))
	case <-runCtx.Done():
		logger.Info("gateway context canceled, shutting down", zap.Error(runCtx.Err()))
	}

	// Graceful shutdown: 12s maximum for workers and a separately preserved
	// finalization window within the overall 15s budget.
	gatewayServing.Store(false)
	kernel.StopAdmission()
	close(userRefreshStop)
	close(systemdStop)
	_ = systemd.Notify("STOPPING=1\nSTATUS=shutting down")
	totalDeadline := time.Now().Add(15 * time.Second)
	workerCtx, workerCancel := context.WithDeadline(context.Background(), time.Now().Add(12*time.Second))
	var workers sync.WaitGroup
	var shutdownErrs errorCollector
	shutdownErrs.Add(inboundManager.Close())
	workers.Add(1)
	go func() { defer workers.Done(); shutdownErrs.Add(inboundManager.Wait(workerCtx)) }()
	for _, service := range httpServices {
		workers.Add(1)
		go func(server *http.Server) {
			defer workers.Done()
			if err := server.Shutdown(workerCtx); err != nil {
				_ = server.Close()
			}
		}(service.server)
	}
	workers.Add(2)
	go func() { defer workers.Done(); kernel.CloseOutbounds() }()
	go func() { defer workers.Done(); background.Wait() }()
	workersDone := make(chan struct{})
	go func() { workers.Wait(); close(workersDone) }()
	select {
	case <-workersDone:
	case <-workerCtx.Done():
		shutdownErrs.Add(fmt.Errorf("worker shutdown: %w", workerCtx.Err()))
		for _, service := range httpServices {
			_ = service.server.Close()
		}
	}
	workerCancel()
	// Wait for context-aware workers to report their final result before
	// taking the aggregate. The total deadline still bounds a non-cooperative
	// worker, leaving the finalization path able to proceed.
	select {
	case <-workersDone:
	case <-time.After(time.Until(totalDeadline)):
	}
	serviceErr = errors.Join(serviceErr, shutdownErrs.Err())
	finalCtx, finalCancel := context.WithDeadline(context.Background(), totalDeadline)
	if err := kernel.StopTraffic(finalCtx); err != nil {
		serviceErr = errors.Join(serviceErr, fmt.Errorf("final traffic flush: %w", err))
	}
	finalCancel()
	if err := store.Close(); err != nil {
		serviceErr = errors.Join(serviceErr, fmt.Errorf("close sqlite: %w", err))
	}
	logger.Info("proxy-gateway stopped")
	return serviceErr
}

// errorCollector accepts shutdown failures from concurrent workers without
// allowing reporting itself to block the bounded shutdown path.
type errorCollector struct {
	mu  sync.Mutex
	err error
}

func (c *errorCollector) Add(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.err = errors.Join(c.err, err)
	c.mu.Unlock()
}

func (c *errorCollector) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runRecordExit(args []string) {
	flags := flag.NewFlagSet("proxy-gateway record-exit", flag.ExitOnError)
	configPath := flags.String("c", "configs/gateway.yaml", "path to config file")
	_ = flags.Parse(args)
	cfg, err := config.LoadRuntime(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config for process record: %v\n", err)
		return
	}
	store, err := storage.NewSQLiteStore(cfg.DBPath, zap.NewNop())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store for process record: %v\n", err)
		return
	}
	defer store.Close()
	pid, _ := strconv.Atoi(os.Getenv("MAINPID"))
	if err := store.RecordProcessExit(pid, os.Getenv("SERVICE_RESULT"), os.Getenv("EXIT_CODE"), os.Getenv("EXIT_STATUS")); err != nil {
		fmt.Fprintf(os.Stderr, "record process exit: %v\n", err)
	}
}

func runRestartScheduler(stop <-chan struct{}, store *storage.SQLiteStore, unit string, logger *zap.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			job, err := store.ClaimDueRestart(time.Now())
			if err != nil {
				logger.Warn("claim restart job", zap.Error(err))
				continue
			}
			if job == nil {
				continue
			}
			if err := systemd.RestartUnit(unit); err != nil {
				logger.Error("scheduled systemd restart failed", zap.Error(err))
				_ = store.CompleteRestartJob(job.ID, false, err.Error())
				continue
			}
			_ = store.CompleteRestartJob(job.ID, true, "")
			return
		}
	}
}

func runWatchdog(stop <-chan struct{}, store *storage.SQLiteStore, gatewayServing *atomic.Bool, logger *zap.Logger) {
	interval := systemd.WatchdogInterval()
	if interval == 0 {
		logger.Info("systemd watchdog enabled in config but WATCHDOG_USEC is unset")
		return
	}
	if err := systemd.Notify("READY=1\nSTATUS=running"); err != nil {
		logger.Warn("systemd ready notification failed", zap.Error(err))
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !gatewayServing.Load() {
				logger.Error("watchdog health check failed: Gateway serve loop is not running")
				continue
			}
			if err := store.Ping(); err != nil {
				logger.Error("watchdog health check failed", zap.Error(err))
				continue
			}
			if err := systemd.Notify("WATCHDOG=1\nSTATUS=healthy"); err != nil {
				logger.Warn("systemd watchdog notification failed", zap.Error(err))
			}
		}
	}
}

func serveHTTP(logger *zap.Logger, name string, server *http.Server, listener net.Listener, errCh chan<- error) {
	logger.Info(name+" starting", zap.String("listen", server.Addr))
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		errCh <- fmt.Errorf("%s stopped: %w", name, err)
	}
}

func refreshUserState(stop <-chan struct{}, store *storage.SQLiteStore, kernel *policy.Kernel, logger *zap.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			loaded, err := store.LoadRuntimeUsers()
			if err != nil {
				logger.Warn("failed to refresh user state", zap.Error(err))
				continue
			}
			kernel.UpdateUsers(loaded)
		}
	}
}
