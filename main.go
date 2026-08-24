package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Kyei-Ernest/DocOps/config"
	"github.com/Kyei-Ernest/DocOps/connectors/local"
	"github.com/Kyei-Ernest/DocOps/handlers"
	"github.com/Kyei-Ernest/DocOps/middleware"
	authsvc "github.com/Kyei-Ernest/DocOps/services/auth"
	"github.com/Kyei-Ernest/DocOps/services/metadata"
	"github.com/go-chi/chi/v5"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Set structured text logging as default
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// ── 1. Load and parse configuration ──────────────────────────
	rawCfg, err := config.Load("config.yaml")
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	cfg, err := config.Parse(rawCfg)
	if err != nil {
		slog.Error("failed to parse config", "error", err)
		os.Exit(1)
	}

	// ── 2. Open shared SQLite connection ─────────────────────────
	// Ensure the parent directory for the database exists before opening.
	dbDir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		slog.Error("failed to create database directory", "dir", dbDir, "error", err)
		os.Exit(1)
	}

	// A single *sql.DB is shared between the user store and metadata
	// store. database/sql manages its own connection pool internally.
	db, err := sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Verify the database is reachable before proceeding.
	if err := db.Ping(); err != nil {
		slog.Error("database ping failed", "error", err)
		os.Exit(1)
	}

	// Metadata store — document CRUD + FTS5 search (runs its own migrations).
	// Built over the SAME *sql.DB pool as the user store so a single
	// transaction can span documents + users tables (atomic key rotation).
	metaStore, err := metadata.NewDB(db)
	if err != nil {
		slog.Error("failed to initialise metadata store", "error", err)
		os.Exit(1)
	}
	defer metaStore.Close()

	// User store — user persistence (runs its own migrations)
	userStore, err := authsvc.NewUserStore(db)
	if err != nil {
		slog.Error("failed to initialise user store", "error", err)
		os.Exit(1)
	}

	// Session store — in-memory, goroutine-safe KEK holder
	sessionStore := authsvc.NewSessionStore()
	defer sessionStore.Close()

	// API key store — stateless machine credentials (ROADMAP P0-1)
	apiKeyStore, err := authsvc.NewAPIKeyStore(db)
	if err != nil {
		slog.Error("failed to initialise api key store", "error", err)
		os.Exit(1)
	}

	// Refresh token store — hash-only durable identities for remember-me
	// revocation/audit across restarts (ROADMAP P1-2)
	refreshStore, err := authsvc.NewRefreshTokenStore(db)
	if err != nil {
		slog.Error("failed to initialise refresh token store", "error", err)
		os.Exit(1)
	}

	// Local storage connector — filesystem-backed file I/O
	connector, err := local.New(cfg.StoragePath)
	if err != nil {
		slog.Error("failed to initialise storage connector", "error", err)
		os.Exit(1)
	}

	// Verify storage is accessible
	if err := connector.Ping(context.Background()); err != nil {
		slog.Error("storage health check failed", "error", err)
		os.Exit(1)
	}

	// ── 4. Construct handlers ────────────────────────────────────
	authHandler := handlers.NewAuthHandlerWithRefresh(userStore, sessionStore, metaStore, refreshStore, &cfg.Argon2, cfg.JWTSecret)
	uploadHandler := handlers.NewUploadHandler(connector, metaStore)
	downloadHandler := handlers.NewDownloadHandler(connector, metaStore)
	searchHandler := handlers.NewSearchHandler(connector, metaStore)
	deleteHandler := handlers.NewDeleteHandler(connector, metaStore)
	healthHandler := handlers.NewHealthHandler(db, connector)
	apiKeyHandler := handlers.NewAPIKeyHandler(apiKeyStore)

	// ── 5. Build router ──────────────────────────────────────────
	r := chi.NewRouter()

	// Ops probes — unauthenticated by design: orchestrators must be able to
	// determine liveness/readiness without holding credentials. /readyz
	// reports component status without leaking internal error detail.
	r.Get("/healthz", healthHandler.Live)
	r.Get("/readyz", healthHandler.Ready)

	// Create an IP-based rate limiter for auth endpoints. Proxy headers are
	// honored only when explicitly configured (trust_proxy_headers) — see
	// models.RateLimitConfig for the spoofing rationale.
	authLimiter := middleware.NewRateLimiterWithTrust(cfg.RateLimitLimit, cfg.RateLimitWindow, cfg.RateLimitTrustProxy)
	defer authLimiter.Close()

	// Document routes get their own, higher ceiling — bearer-driven machine
	// traffic is the primary consumer and must not trip the auth-tier limit.
	docsLimiter := middleware.NewRateLimiterWithTrust(cfg.DocsRateLimitLimit, cfg.DocsRateLimitWindow, cfg.RateLimitTrustProxy)
	defer docsLimiter.Close()

	// Auth routes — rate limited using config values
	r.Route("/v0.1/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(authLimiter.Limit)
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)
			r.Post("/recover", authHandler.Recover)
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.AuthWithAPIKeys(sessionStore, cfg.JWTSecret, apiKeyStore))
			r.Post("/change-password", authHandler.ChangePassword)
			r.Post("/rotate-master-key", authHandler.RotateMasterKey)

			// Machine credential lifecycle (P0-1). Creating requires a live
			// session/bearer context to wrap the current Master Key.
			r.Post("/api-keys", apiKeyHandler.Create)
			r.Get("/api-keys", apiKeyHandler.List)
			r.Delete("/api-keys/{keyID}", apiKeyHandler.Revoke)
		})
	})

	// Document routes — protected by combined middleware: humans via cookie
	// sessions, machines via Bearer docops_sk_… keys (stateless per request).
	r.Route("/v0.1/docs", func(r chi.Router) {
		r.Use(docsLimiter.Limit)
		r.Use(middleware.AuthWithAPIKeys(sessionStore, cfg.JWTSecret, apiKeyStore))

		r.Post("/upload", uploadHandler.Upload)
		r.Get("/{docID}/download", downloadHandler.Download)
		r.Get("/search", searchHandler.Search)
		r.Delete("/{docID}", deleteHandler.Delete)
	})

	// ── 5b. TTL sweeper ──────────────────────────────────────────
	// Deletes expired document objects from storage, then their metadata
	// rows (file-first so failures orphan a row, never a dangling pointer).
	// One sweep at startup cleans crash leftovers; then hourly.
	sweepOnce := func(ctx context.Context) {
		keys, err := metaStore.ExpiredStorageKeys(ctx, time.Now())
		if err != nil {
			slog.Error("ttl sweep list failed", "error", err)
			return
		}
		for _, key := range keys {
			if err := connector.Delete(ctx, key); err != nil {
				slog.Error("ttl sweep object delete failed", "key", key, "error", err)
				continue
			}
		}
		if n, err := metaStore.DeleteExpiredRows(ctx, time.Now()); err != nil {
			slog.Error("ttl sweep row delete failed", "error", err)
		} else if n > 0 {
			slog.Info("ttl sweep removed expired documents", "count", n)
		}
	}
	sweepCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()
	sweepOnce(sweepCtx)
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sweepOnce(sweepCtx)
			case <-sweepCtx.Done():
				return
			}
		}
	}()

	// ── 6. Start HTTP server ─────────────────────────────────────
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	//
	// srv.Shutdown stops listeners immediately and waits for in-flight
	// requests to finish (bounded by the timeout), unlike srv.Close which
	// kills active connections mid-request — an upload truncated halfway
	// through would otherwise leave an orphaned or partial ciphertext file.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Warn("received shutdown signal, draining connections...", "signal", sig.String())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown timed out; forcing close", "error", err)
			srv.Close()
		}
	}()

	slog.Info("DocOps server starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}
