package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openwaf-dev/egress/pkg/egress"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "Path to Egress Gateway config JSON (or /etc/openwaf/egress.json)")
	listenAddr := flag.String("addr", "", "Override listening address (e.g. :8070)")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log.Printf("[EGRESS] Starting OpenWAF Egress Gateway %s...", version)

	cfg, err := egress.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[EGRESS] Failed loading config from %s: %v", *configPath, err)
	}

	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}

	var vault egress.SecretProvider
	if cfg.OpenBao.Addr != "" {
		vClient, err := egress.NewVaultClient(cfg.OpenBao)
		if err != nil {
			log.Fatalf("[EGRESS] Failed initializing OpenBao client: %v", err)
		}
		vault = vClient
		log.Printf("[EGRESS] OpenBao configured at %s", cfg.OpenBao.Addr)
	} else {
		log.Println("[EGRESS] WARN: OpenBao address not configured; credential injection disabled")
	}

	srv := egress.NewServer(cfg, vault)

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 300 * time.Second, // Long timeout for streaming LLMs
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[EGRESS] Listening on %s (agents: %d, targets: %d)", cfg.ListenAddr, len(cfg.Agents), len(cfg.Targets))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[EGRESS] Listen error: %v", err)
		}
	}()

	<-stop
	log.Println("[EGRESS] Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[EGRESS] Forced shutdown error: %v", err)
	}
	log.Println("[EGRESS] Stopped.")
}
