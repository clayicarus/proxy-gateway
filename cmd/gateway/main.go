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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/api"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/subtoken"
	"github.com/clayicarus/proxy-gateway/internal/systemd"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "record-exit" {
		runRecordExit(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrate(os.Args[2:])
		return
	}
	if err := runGateway(os.Args[1:]); err != nil {
		os.Exit(1)
	}
}

func runGateway(args []string) error {
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
	users, err := store.LoadRuntimeUsers()
	if err != nil {
		_ = store.Close()
		return fmt.Errorf("load managed users: %w", err)
	}
	nodes, err := store.LoadNodes()
	if err != nil {
		_ = store.Close()
		return fmt.Errorf("load managed nodes: %w", err)
	}
	location, _ := time.LoadLocation(cfg.Timezone)
	logger.Info("runtime configuration loaded", zap.Int("users", len(users)), zap.Int("nodes", len(nodes)))

	// Initialize shared components.
	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLoggerWithLocation(users, store, logger, location)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := router.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)
	connectionTracker := connection.NewTracker()

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
	type inboundService struct {
		name   string
		server hyServer.Server
	}
	var httpServices []httpService
	var inboundServices []inboundService
	cleanupConstructed := func() {
		for _, service := range httpServices {
			_ = service.listener.Close()
		}
		for _, service := range inboundServices {
			_ = service.server.Close()
		}
		outboundFactory.Close()
		_ = store.Close()
	}

	adminListen := cfg.Admin.Listen
	if adminListen != "" {
		if !isLoopbackListen(adminListen) {
			cleanupConstructed()
			return fmt.Errorf("management web must listen on a loopback address: %s", adminListen)
		}
		manager, err := api.NewManager(cfg, store, trafficLogger, logger, connectionTracker)
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("create management web: %w", err)
		}
		manager.SetNodeStatusProvider(outboundFactory)
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
	for _, inbound := range cfg.Inbounds {
		udpAddr, err := net.ResolveUDPAddr("udp", inbound.Listen)
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("resolve inbound %s listen: %w", inbound.Name, err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			cleanupConstructed()
			return fmt.Errorf("inbound %s listen: %w", inbound.Name, err)
		}
		adapter := hyInbound.New(inbound.Name, authenticator, routingService, trafficLogger, connectionTracker, logger)
		server, err := hyServer.NewServer(&hyServer.Config{
			TLSConfig:  hyServer.TLSConfig{Certificates: []tls.Certificate{tlsCert}},
			QUICConfig: buildInboundQUICConfig(inbound.QUIC), Conn: udpConn,
			SessionAuthenticator: adapter, SessionOutbound: adapter,
			SessionTrafficLogger: adapter, SessionEventLogger: adapter,
		})
		if err != nil {
			_ = udpConn.Close()
			cleanupConstructed()
			return fmt.Errorf("construct inbound %s: %w", inbound.Name, err)
		}
		inboundServices = append(inboundServices, inboundService{name: inbound.Name, server: server})
	}

	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := outboundFactory.Warmup(warmupCtx); err != nil {
		logger.Warn("node warmup incomplete; startup will continue", zap.Error(err))
	}
	warmupCancel()
	trafficLogger.StartPeriodicFlush(cfg.TrafficFlushInterval)
	serviceErrCh := make(chan error, len(httpServices)+len(inboundServices))
	for _, service := range httpServices {
		go serveHTTP(logger, service.name, service.server, service.listener, serviceErrCh)
	}

	// Only user lifecycle fields are hot-reloaded. Node definitions and route
	// authorization remain the startup snapshot and require a full restart.
	userRefreshStop := make(chan struct{})
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		defer background.Done()
		refreshUserState(userRefreshStop, store, users, authenticator, trafficLogger, logger)
	}()

	systemdStop := make(chan struct{})

	logger.Info("proxy-gateway starting", zap.Int("inbounds", len(inboundServices)))
	var gatewayServing atomic.Bool
	gatewayServing.Store(true)
	for _, service := range inboundServices {
		go func(service inboundService) {
			err := service.server.Serve()
			if err == nil {
				err = fmt.Errorf("serve loop stopped without an error")
			}
			serviceErrCh <- fmt.Errorf("inbound %s stopped: %w", service.name, err)
		}(service)
	}

	state, err := store.GetConfigState()
	if err != nil {
		logger.Warn("failed to read config revision", zap.Error(err))
	} else {
		if _, err := store.StartProcessRun(os.Getpid(), state.Revision, os.Getenv("HY2_RESTART_TRIGGER")); err != nil {
			logger.Warn("failed to record process start", zap.Error(err))
		}
		if err := store.SetActiveRevision(state.Revision); err != nil {
			logger.Warn("failed to record active config revision", zap.Error(err))
		}
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var serviceErr error
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case serviceErr = <-serviceErrCh:
		logger.Error("service error", zap.Error(serviceErr))
	case <-ctx.Done():
	}

	// Graceful shutdown: 12s maximum for workers and a separately preserved
	// finalization window within the overall 15s budget.
	gatewayServing.Store(false)
	trafficLogger.StopAdmission()
	close(userRefreshStop)
	close(systemdStop)
	_ = systemd.Notify("STOPPING=1\nSTATUS=shutting down")
	totalDeadline := time.Now().Add(15 * time.Second)
	workerCtx, workerCancel := context.WithDeadline(context.Background(), time.Now().Add(12*time.Second))
	var workers sync.WaitGroup
	shutdownErrCh := make(chan error, len(inboundServices)+1)
	addShutdownErr := func(err error) {
		if err != nil {
			shutdownErrCh <- err
		}
	}
	for _, service := range inboundServices {
		_ = service.server.Close()
		workers.Add(1)
		go func(server hyServer.Server) { defer workers.Done(); addShutdownErr(server.Wait(workerCtx)) }(service.server)
	}
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
	go func() { defer workers.Done(); outboundFactory.Close() }()
	go func() { defer workers.Done(); background.Wait() }()
	workersDone := make(chan struct{})
	go func() { workers.Wait(); close(workersDone) }()
	select {
	case <-workersDone:
	case <-workerCtx.Done():
		addShutdownErr(fmt.Errorf("worker shutdown: %w", workerCtx.Err()))
		for _, service := range httpServices {
			_ = service.server.Close()
		}
	}
	workerCancel()
	for {
		select {
		case err := <-shutdownErrCh:
			serviceErr = errors.Join(serviceErr, err)
		default:
			goto shutdownErrorsDrained
		}
	}

shutdownErrorsDrained:
	finalCtx, finalCancel := context.WithDeadline(context.Background(), totalDeadline)
	if err := trafficLogger.StopContext(finalCtx); err != nil {
		serviceErr = errors.Join(serviceErr, fmt.Errorf("final traffic flush: %w", err))
	}
	finalCancel()
	if err := store.Close(); err != nil {
		serviceErr = errors.Join(serviceErr, fmt.Errorf("close sqlite: %w", err))
	}
	logger.Info("proxy-gateway stopped")
	return serviceErr
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

func refreshUserState(stop <-chan struct{}, store *storage.SQLiteStore, active map[string]config.UserConfig, authenticator *auth.Authenticator, trafficLogger *traffic.TrafficLogger, logger *zap.Logger) {
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
			// Preserve the startup routes. This applies deletion, expiry,
			// passwords, quota and speed immediately while leaving any user-node
			// authorization change pending until restart.
			updated := make(map[string]config.UserConfig, len(active))
			for username, startupUser := range active {
				if user, ok := loaded[username]; ok {
					user.Routes = append([]string(nil), startupUser.Routes...)
					updated[username] = user
				} else {
					startupUser.Disabled = true
					updated[username] = startupUser
				}
			}
			authenticator.UpdateUsers(updated)
			trafficLogger.UpdateUsers(updated)
		}
	}
}

func runMigrate(args []string) {
	flags := flag.NewFlagSet("proxy-gateway migrate", flag.ExitOnError)
	configPath := flags.String("c", "configs/gateway.yaml", "path to legacy config file")
	replaceUsers := flags.Bool("replace-users", false, "replace managed users and routes while retaining nodes and traffic")
	_ = flags.Parse(args)

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("failed to load legacy config", zap.Error(err))
	}
	secret := cfg.API.Secret
	if cfg.Sub != nil && cfg.Sub.Secret != "" {
		secret = cfg.Sub.Secret
	}
	if secret == "" {
		logger.Fatal("legacy subscription secret is required (sub.secret or api.secret)")
	}
	store, err := storage.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		logger.Fatal("failed to open sqlite store", zap.Error(err))
	}
	defer store.Close()
	legacyToken := func(username string) string { return subtoken.Legacy(username, secret) }
	if *replaceUsers {
		if err := store.ReplaceLegacyUsers(cfg, legacyToken); err != nil {
			logger.Fatal("legacy user replacement failed", zap.Error(err))
		}
		logger.Info("legacy users replaced; restart Gateway to apply them", zap.Int("users", len(cfg.Users)))
		return
	}
	if err := store.MigrateLegacy(cfg, legacyToken); err != nil {
		if strings.Contains(err.Error(), "managed user data already exists") || strings.Contains(err.Error(), "already been migrated") {
			err = fmt.Errorf("%w; use migrate --replace-users only when you intend to replace all managed users", err)
		}
		logger.Fatal("legacy migration failed", zap.Error(err))
	}
	logger.Info("legacy YAML migration completed", zap.Int("users", len(cfg.Users)), zap.Int("nodes", len(cfg.Nodes)))
}

func buildInboundQUICConfig(input *config.QUICConfig) hyServer.QUICConfig {
	qc := hyServer.QUICConfig{}
	if input != nil {
		qc.InitialStreamReceiveWindow = input.InitStreamReceiveWindow
		qc.MaxStreamReceiveWindow = input.MaxStreamReceiveWindow
		qc.InitialConnectionReceiveWindow = input.InitConnReceiveWindow
		qc.MaxConnectionReceiveWindow = input.MaxConnReceiveWindow
		qc.MaxIdleTimeout = input.MaxIdleTimeout
		qc.MaxIncomingStreams = input.MaxIncomingStreams
		qc.DisablePathMTUDiscovery = input.DisablePathMTUDiscovery
	}
	return qc
}
