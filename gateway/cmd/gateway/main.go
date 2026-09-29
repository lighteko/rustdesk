package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	gateway "github.com/lighteko/rustdesk/gateway"
)

func main() {
	path := flag.String("config", "config.json", "configuration path")
	flag.Parse()
	cfg, err := gateway.LoadConfig(*path)
	if err != nil {
		slog.Error("configuration", "error", err)
		os.Exit(1)
	}
	s, err := gateway.New(cfg)
	if err != nil {
		slog.Error("initialize", "error", err)
		os.Exit(1)
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.Run(ctx)
	httpServer := &http.Server{Addr: cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown", "error", err)
		}
	}()
	slog.Info("gateway listening", "address", cfg.Listen, "origin", cfg.Origin, "rustdesk_proxy", cfg.EnableRustDeskProxy)
	if err = httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}
