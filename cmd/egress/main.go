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

	"github.com/openwaf-dev/egress/pkg/controlplane"
	"github.com/openwaf-dev/egress/pkg/egress"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen(os.Args[2:])
		return
	}

	pollDefault := envDuration("OPENWAF_POLL_INTERVAL", 15*time.Second)
	staleDefault := envDuration("OPENWAF_MAX_STALE", 10*time.Minute)

	configPath := flag.String("config", "config.json", "Path to Egress Gateway config JSON (or /etc/openwaf/egress.json)")
	listenAddr := flag.String("addr", "", "Override listening address (e.g. :8070)")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	controlPlane := flag.String("control-plane", os.Getenv("OPENWAF_CONTROL_PLANE"), "OpenWAF Cloud URL (e.g. https://app.openwaf.dev): take agents and targets from the control plane instead of the config file (env OPENWAF_CONTROL_PLANE)")
	nodeID := flag.String("node-id", os.Getenv("OPENWAF_NODE_ID"), "Node id registered in OpenWAF Cloud (env OPENWAF_NODE_ID)")
	nodeKey := flag.String("node-key", os.Getenv("OPENWAF_NODE_KEY"), "Path to the node's ed25519 PKCS#8 PEM private key (env OPENWAF_NODE_KEY)")
	trusted := flag.String("trusted-proxies", os.Getenv("OPENWAF_TRUSTED_PROXIES"), "Comma-separated addresses or CIDRs of reverse proxies in front of the gateway whose X-Real-IP gives the caller address of block events, e.g. 127.0.0.1 (env OPENWAF_TRUSTED_PROXIES)")
	pollInterval := flag.Duration("poll-interval", pollDefault, "How often to poll the control plane configuration (env OPENWAF_POLL_INTERVAL)")
	maxStale := flag.Duration("max-stale", staleDefault, "How long the last configuration stays in force when the control plane cannot confirm it; then requests answer 503 (env OPENWAF_MAX_STALE)")
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

	ctx, stopBackground := context.WithCancel(context.Background())
	var background []<-chan struct{}
	run := func(f func(context.Context)) {
		done := make(chan struct{})
		background = append(background, done)
		go func() { f(ctx); close(done) }()
	}

	proxies, err := egress.ParsePrefixes(*trusted)
	if err != nil {
		log.Fatalf("[EGRESS] -trusted-proxies: %v", err)
	}
	opts := []egress.Option{egress.WithTrustedProxies(proxies)}

	var srv *egress.Server
	var stats egress.ResolverStats = cfg
	if *controlPlane == "" {
		srv = egress.NewServer(cfg, vault, opts...)
	} else {
		if *nodeID == "" || *nodeKey == "" {
			log.Fatal("[EGRESS] -control-plane needs -node-id and -node-key")
		}
		key, err := controlplane.LoadPrivateKey(*nodeKey)
		if err != nil {
			log.Fatalf("[EGRESS] %v", err)
		}
		signer, err := controlplane.NewSigner(*nodeID, key)
		if err != nil {
			log.Fatalf("[EGRESS] %v", err)
		}
		client, err := controlplane.NewClient(*controlPlane, signer, nil)
		if err != nil {
			log.Fatalf("[EGRESS] %v", err)
		}
		if len(cfg.Agents) > 0 || len(cfg.Targets) > 0 {
			log.Printf("[EGRESS] Control-plane mode: ignoring %d agents and %d targets of %s", len(cfg.Agents), len(cfg.Targets), *configPath)
		}
		if vault == nil {
			log.Println("[EGRESS] WARN: without OpenBao every control-plane request is refused (no credential to inject)")
		}

		if *pollInterval <= 0 || *maxStale <= 0 {
			log.Fatal("[EGRESS] -poll-interval and -max-stale must be positive")
		}
		if *maxStale < 2**pollInterval {
			log.Printf("[EGRESS] WARN: -max-stale %s is less than two poll intervals (%s); one missed poll makes requests answer 503", *maxStale, *pollInterval)
		}
		resolver := controlplane.NewResolver(client, controlplane.ResolverOptions{Interval: *pollInterval, MaxStale: *maxStale})
		first, cancel := context.WithTimeout(ctx, 10*time.Second)
		if _, err := resolver.Refresh(first); err != nil {
			log.Printf("[EGRESS] WARN: first control plane config fetch failed (requests answer 503 until one succeeds): %v", err)
		}
		cancel()
		sink := controlplane.NewEventSink(client, controlplane.EventSinkOptions{})
		run(resolver.Run)
		run(sink.Run)
		srv = egress.NewServerWithResolver(resolver, vault, append(opts, egress.WithEventSink(sink))...)
		stats = resolver
		log.Printf("[EGRESS] Control plane %s as node %s (key id %s), polling every %s, max stale %s", *controlPlane, signer.NodeID(), signer.KeyID(), *pollInterval, *maxStale)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      egress.UpstreamTimeout, // a streamed generation is one write window
		IdleTimeout:       120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		agents, targets := stats.Counts()
		log.Printf("[EGRESS] Listening on %s (agents: %d, targets: %d)", cfg.ListenAddr, agents, targets)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[EGRESS] Listen error: %v", err)
		}
	}()

	<-stop
	log.Println("[EGRESS] Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[EGRESS] Forced shutdown error: %v", err)
	}
	// Stop polling and deliver the queued block events.
	stopBackground()
	for _, done := range background {
		<-done
	}
	log.Println("[EGRESS] Stopped.")
}

// envDuration reads a positive duration from the environment variable name, or returns def.
func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Fatalf("[EGRESS] Invalid %s %q", name, v)
	}
	return d
}

// keygen writes a new node private key and prints its public key, the value an operator
// registers with POST /v1/egress/nodes.
func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "node.key", "Where to write the new ed25519 PKCS#8 PEM private key (mode 0600, never overwritten)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: egress keygen [-out node.key]\n\nWrites a node private key and prints its public key (standard base64 of the raw 32 bytes).")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	pub, err := controlplane.GenerateKeyFile(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "egress keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Private key written to %s (key id %s). Register the public key below with POST /v1/egress/nodes.\n", *out, controlplane.KeyID(pub))
	fmt.Println(controlplane.PublicKeyBase64(pub))
}
