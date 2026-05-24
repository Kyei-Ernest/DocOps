package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
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
	// ── 1. Load and parse configuration ──────────────────────────
	rawCfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cfg, err := config.Parse(rawCfg)
	if err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	// ── 2. Open shared SQLite connection ─────────────────────────
	// Ensure the parent directory for the database exists before opening.
	dbDir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Fatalf("failed to create database directory %q: %v", dbDir, err)
	}

	// A single *sql.DB is shared between the user store and metadata
	// store. database/sql manages its own connection pool internally.
	db, err := sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Verify the database is reachable before proceeding.
	if err := db.Ping(); err != nil {
		log.Fatalf("database ping failed: %v", err)
	}

	// ── 3. Initialise services ───────────────────────────────────
	// Metadata store — document CRUD + FTS5 search (runs its own migrations)
	metaStore, err := metadata.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("failed to initialise metadata store: %v", err)
	}
	defer metaStore.Close()

	// User store — user persistence (runs its own migrations)
	userStore, err := authsvc.NewUserStore(db)
	if err != nil {
		log.Fatalf("failed to initialise user store: %v", err)
	}

	// Session store — in-memory, goroutine-safe KEK holder
	sessionStore := authsvc.NewSessionStore()

	// Local storage connector — filesystem-backed file I/O
	connector, err := local.New(cfg.StoragePath)
	if err != nil {
		log.Fatalf("failed to initialise storage connector: %v", err)
	}

	// Verify storage is accessible
	if err := connector.Ping(context.Background()); err != nil {
		log.Fatalf("storage health check failed: %v", err)
	}

	// ── 4. Construct handlers ────────────────────────────────────
	authHandler := handlers.NewAuthHandler(userStore, sessionStore, &cfg.Argon2, cfg.JWTSecret)
	uploadHandler := handlers.NewUploadHandler(connector, metaStore)
	downloadHandler := handlers.NewDownloadHandler(connector, metaStore)
	searchHandler := handlers.NewSearchHandler(connector, metaStore)
	deleteHandler := handlers.NewDeleteHandler(connector, metaStore)

	// ── 5. Build router ──────────────────────────────────────────
	r := chi.NewRouter()

	// Auth routes — no middleware required (these issue tokens)
	r.Route("/v0.1/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.Refresh)
		r.Post("/logout", authHandler.Logout)
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
		log.Printf("received %v, shutting down...", sig)
		srv.Close()
	}()

	log.Printf("DocOps server starting on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("server stopped")
}
