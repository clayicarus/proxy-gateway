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
	"syscall"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/api"
	"github.com/hy2-gateway/internal/auth"
	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/event"
	"github.com/hy2-gateway/internal/router"
	"github.com/hy2-gateway/internal/storage"
	"github.com/hy2-gateway/internal/traffic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	configPath := flag.String("c", "configs/gateway.yaml", "path to config file")
	flag.Parse()

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
		zap.Int("users", len(cfg.Users)),
		zap.Int("nodes", len(cfg.Nodes)),
	)

	// Initialize SQLite store
	store, err := storage.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		logger.Fatal("failed to open sqlite store", zap.Error(err))
	}
	defer store.Close()
	logger.Info("sqlite store opened", zap.String("path", cfg.DBPath))

	// Initialize components
	authenticator := auth.NewAuthenticator(cfg.Users, logger)
	trafficLogger := traffic.NewTrafficLogger(cfg.Users, store, logger)
	routerEngine := router.NewRouter(logger)
	outboundFactory := router.NewOutboundFactory(cfg.Nodes, logger)
	routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
	eventLogger := event.NewEventLogger(routingOutbound, logger)

	// Start periodic traffic flush to SQLite
	trafficLogger.StartPeriodicFlush(cfg.TrafficFlushInterval)

	logger.Info("all components initialized")

	// Start management API
	if cfg.API.Listen != "" {
		apiServer := api.NewServer(cfg, trafficLogger, cfg.API.Secret, logger)
		httpServer := &http.Server{
			Addr:    cfg.API.Listen,
			Handler: apiServer.Handler(),
		}
		go func() {
			logger.Info("management API starting", zap.String("listen", cfg.API.Listen))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("API server error", zap.Error(err))
			}
		}()
	}

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
		BandwidthConfig: hyServer.BandwidthConfig{
			MaxTx: parseBandwidth(cfg.Bandwidth, true),
			MaxRx: parseBandwidth(cfg.Bandwidth, false),
		},
	})
	if err != nil {
		logger.Fatal("failed to create hysteria2 server", zap.Error(err))
	}

	logger.Info("hy2-gateway starting", zap.String("listen", cfg.Listen))

	// Start serving in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- hyServerInstance.Serve()
	}()

	// Wait for shutdown signal or server error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case err := <-errCh:
		logger.Error("server error", zap.Error(err))
	case <-ctx.Done():
	}

	// Graceful shutdown
	hyServerInstance.Close()
	outboundFactory.Close()
	trafficLogger.Stop()
	logger.Info("hy2-gateway stopped")
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

func parseBandwidth(bw *config.BandwidthConfig, isTx bool) uint64 {
	if bw == nil {
		return 0
	}
	// Simple parsing — in production, use hysteria's bandwidth parser
	// For now, return 0 (no limit) if not configured
	return 0
}
