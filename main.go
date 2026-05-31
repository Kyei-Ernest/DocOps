package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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

	// Metadata store — document CRUD + FTS5 search (runs its own migrations)
	metaStore, err := metadata.New(cfg.DatabasePath)
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
	authHandler := handlers.NewAuthHandler(userStore, sessionStore, metaStore, &cfg.Argon2, cfg.JWTSecret)
	uploadHandler := handlers.NewUploadHandler(connector, metaStore)
	downloadHandler := handlers.NewDownloadHandler(connector, metaStore)
	searchHandler := handlers.NewSearchHandler(connector, metaStore)
	deleteHandler := handlers.NewDeleteHandler(connector, metaStore)

	// ── 5. Build router ──────────────────────────────────────────
	r := chi.NewRouter()

	// Create an IP-based rate limiter for auth endpoints
	authLimiter := middleware.NewRateLimiter(cfg.RateLimitLimit, cfg.RateLimitWindow)
	defer authLimiter.Close()

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
			r.Use(middleware.Auth(sessionStore, cfg.JWTSecret))
			r.Post("/change-password", authHandler.ChangePassword)
			r.Post("/rotate-master-key", authHandler.RotateMasterKey)
		})
	})

	// Document routes — all protected by auth middleware
	r.Route("/v0.1/docs", func(r chi.Router) {
		r.Use(middleware.Auth(sessionStore, cfg.JWTSecret))

		r.Post("/upload", uploadHandler.Upload)
		r.Get("/{docID}/download", downloadHandler.Download)
		r.Get("/search", searchHandler.Search)
		r.Delete("/{docID}", deleteHandler.Delete)
	})

	// ── 6. Start HTTP server ─────────────────────────────────────
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Warn("received shutdown signal, shutting down server...", "signal", sig.String())
		srv.Close()
	}()

	slog.Info("DocOps server starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}
