package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/config"
	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/server"
)

// version is set at build time
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("The bridge stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/bridge/config.yaml", "path of the YAML configuration")
	check := flag.Bool("check", false, "validate the configuration, discover the IdPs and exit")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Every IdP is discovered before the bridge serves anything, so a wrong issuer fails the rollout instead of the first sign-in
	discoverCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	srv, err := server.New(discoverCtx, cfg, server.Options{Logger: logger})
	cancel()
	if err != nil {
		return err
	}
	if *check {
		logger.Info("The configuration is valid", slog.Int("resources", len(cfg.Resources)))
		return nil
	}

	servers := []*http.Server{
		{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute},
		{Addr: cfg.MetricsListen, Handler: srv.MetricsHandler(), ReadHeaderTimeout: 10 * time.Second},
	}
	errs := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("listen on %s: %w", s.Addr, err)
			}
		}()
	}
	logger.Info("The bridge is running", slog.String("version", version), slog.String("issuer", cfg.Issuer), slog.String("listen", cfg.Listen), slog.String("metrics_listen", cfg.MetricsListen))

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	// In-flight sign-ins finish, while new connections go to other replicas
	logger.Info("Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	return nil
}
