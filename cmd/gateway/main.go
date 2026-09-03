package main

import (
	"context"
	"crypto/tls"
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
	"github.com/clayicarus/proxy-gateway/internal/event"
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
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}
	logger.Info("config loaded",
		zap.String("listen", cfg.Listen),
	)

	// Initialize SQLite store
	store, err := storage.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		logger.Fatal("failed to open sqlite store", zap.Error(err))
	}
	defer store.Close()
	logger.Info("sqlite store opened", zap.String("path", cfg.DBPath))

	// Load the restart-applied database snapshot. An empty database is valid;
	// the local management Web creates the first users and nodes.
	users, err := store.LoadRuntimeUsers()
	if err != nil {
		logger.Fatal("failed to load managed users", zap.Error(err))
	}
	nodes, err := store.LoadNodes()
	if err != nil {
		logger.Fatal("failed to load managed nodes", zap.Error(err))
	}
	location, _ := time.LoadLocation(cfg.Timezone)
	logger.Info("runtime configuration loaded", zap.Int("users", len(users)), zap.Int("nodes", len(nodes)))

	// Initialize components
	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLoggerWithLocation(users, store, logger, location)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := router.NewOutboundFactory(nodes, logger)
	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := outboundFactory.Warmup(warmupCtx); err != nil {
		logger.Warn("node warmup incomplete; startup will continue", zap.Error(err))
	}
	warmupCancel()
	routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
	connectionTracker := connection.NewTracker()
	eventLogger := event.NewEventLogger(routingOutbound, logger, connectionTracker)

	// Start periodic traffic flush to SQLite
	trafficLogger.StartPeriodicFlush(cfg.TrafficFlushInterval)

	logger.Info("all components initialized")

	// Start local management Web and, when configured, the separate public
	// subscription listener. The old api.listen value is accepted as a legacy
	// alias for admin.listen but no longer grants a JSON management API.
	var httpServers []*http.Server
	serviceErrCh := make(chan error, 3)
	adminListen := cfg.Admin.Listen
	if adminListen == "" {
		adminListen = cfg.API.Listen
	}
	if adminListen != "" {
		if !isLoopbackListen(adminListen) {
			logger.Fatal("management web must listen on a loopback address", zap.String("listen", adminListen))
		}
		manager, err := api.NewManager(cfg, store, trafficLogger, logger, connectionTracker)
		if err != nil {
			logger.Fatal("failed to create management web", zap.Error(err))
		}
		manager.SetNodeStatusProvider(outboundFactory)
		httpServer := &http.Server{Addr: adminListen, Handler: manager.Handler(), ReadHeaderTimeout: 10 * time.Second}
		listener, err := net.Listen("tcp", adminListen)
		if err != nil {
			logger.Fatal("management web failed to listen", zap.String("listen", adminListen), zap.Error(err))
		}
		httpServers = append(httpServers, httpServer)
		go serveHTTP(logger, "management web", httpServer, listener, serviceErrCh)
	}
	if cfg.Sub != nil && cfg.Sub.Listen != "" {
		httpServer := &http.Server{Addr: cfg.Sub.Listen, Handler: api.NewDatabaseSubscriptionHandler(cfg, store, users, nodes, logger).Handler(), ReadHeaderTimeout: 10 * time.Second}
		listener, err := net.Listen("tcp", cfg.Sub.Listen)
		if err != nil {
			logger.Fatal("subscription service failed to listen", zap.String("listen", cfg.Sub.Listen), zap.Error(err))
		}
		httpServers = append(httpServers, httpServer)
		go serveHTTP(logger, "subscription service", httpServer, listener, serviceErrCh)
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

	// Create UDP listener for QUIC
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		logger.Fatal("failed to resolve listen address", zap.Error(err))
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Fatal("failed to listen UDP", zap.Error(err))
	}

	// Load TLS certificate
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		logger.Fatal("failed to load TLS certificate", zap.Error(err))
	}

	// Create Hysteria2 server
	hyServerInstance, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{tlsCert},
		},
		QUICConfig:    buildQUICConfig(cfg),
		Conn:          udpConn,
		Authenticator: authenticator,
		Outbound:      routingOutbound,
		TrafficLogger: trafficLogger,
		EventLogger:   eventLogger,
	})
	if err != nil {
		logger.Fatal("failed to create hysteria2 server", zap.Error(err))
	}

	logger.Info("proxy-gateway starting", zap.String("listen", cfg.Listen))

	// Start serving in background
	var gatewayServing atomic.Bool
	go func() {
		gatewayServing.Store(true)
		defer gatewayServing.Store(false)
		err := hyServerInstance.Serve()
		if err == nil {
			err = fmt.Errorf("serve loop stopped without an error")
		}
		serviceErrCh <- fmt.Errorf("Gateway server stopped: %w", err)
	}()

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

	// Graceful shutdown
	close(userRefreshStop)
	close(systemdStop)
	_ = systemd.Notify("STOPPING=1\nSTATUS=shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	for _, server := range httpServers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP server shutdown failed", zap.Error(err))
		}
	}
	shutdownCancel()
	hyServerInstance.Close()
	outboundFactory.Close()
	background.Wait()
	trafficLogger.Stop()
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
	cfg, err := config.Load(*configPath)
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

func buildQUICConfig(cfg *config.Config) hyServer.QUICConfig {
	qc := hyServer.QUICConfig{}
	if cfg.QUIC != nil {
		qc.InitialStreamReceiveWindow = cfg.QUIC.InitStreamReceiveWindow
		qc.MaxStreamReceiveWindow = cfg.QUIC.MaxStreamReceiveWindow
		qc.InitialConnectionReceiveWindow = cfg.QUIC.InitConnReceiveWindow
		qc.MaxConnectionReceiveWindow = cfg.QUIC.MaxConnReceiveWindow
		qc.MaxIdleTimeout = cfg.QUIC.MaxIdleTimeout
		qc.MaxIncomingStreams = cfg.QUIC.MaxIncomingStreams
		qc.DisablePathMTUDiscovery = cfg.QUIC.DisablePathMTUDiscovery
	}
	return qc
}
