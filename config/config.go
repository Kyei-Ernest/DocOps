// Package config loads and parses DocOps YAML configuration with safe defaults,
// resolves paths, and injects secrets from the environment (never from files).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Kyei-Ernest/DocOps/models"
	"github.com/joho/godotenv"

	"gopkg.in/yaml.v3"
)

// Load reads a YAML config file from path and returns a populated *models.Config.
//
// Defaults are applied first, so a minimal or absent config file still produces
// a usable application. Fields present in the file override the defaults;
// fields omitted in the file retain their default values (yaml.Unmarshal is
// additive, not replacing).
//
// If the file does not exist, Load returns the defaults silently — this lets
// the binary run out of the box without requiring a config file.
//
// All relative paths in the returned config are resolved to absolute paths
// so behaviour is identical regardless of the working directory at startup.
func Load(path string) (*models.Config, error) {
	// Populate defaults before touching the file. yaml.Unmarshal will
	// overwrite only the fields explicitly set in the YAML, leaving
	// everything else at these values.
	cfg := &models.Config{
		Server: models.ServerConfig{
			Port:         8080,
			ReadTimeout:  "30s",
			WriteTimeout: "30s",
		},
		Auth: models.AuthConfig{
			AccessTokenTTL:  "15m",
			RefreshTokenTTL: "168h", // 7 days
		},
		Argon2: models.Argon2Config{
			Memory:      65536, // 64 MiB — minimum recommended for interactive logins
			Iterations:  3,
			Parallelism: 2,
			KeyLength:   32, // 256-bit KEK
			SaltLength:  16, // 128-bit salt
		},
		Storage: models.StorageConfig{
			Local: models.LocalStorageConfig{
				Path: defaultStoragePath(),
			},
		},
		Database: models.DatabaseConfig{
			Path: defaultDBPath(),
		},
		RateLimit: models.RateLimitConfig{
			Limit:  5,
			Window: "1m",
			// Spoofable headers are ignored unless explicitly opted into —
			// see models.RateLimitConfig.TrustProxyHeaders.
			TrustProxyHeaders: false,
			Documents: models.RateLimitSubConfig{
				Limit:  120, // machine-friendly default for document routes
				Window: "1m",
			},
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// Config file missing or unreadable — return defaults so the binary
		// can start without a config file present.
		// Note: permission errors are also silently swallowed here. If stricter
		// behaviour is needed, gate on os.IsNotExist(err) and surface the rest.
		return cfg, nil
	}

	// Unmarshal overlays file values onto the defaults.
	// Because cfg is already populated, fields absent from the YAML are
	// left at their default values rather than zeroed out.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Resolve paths after parsing so user-supplied relative paths (e.g. "./my-data")
	// are anchored to the process working directory, just like the defaults.
	cfg.Storage.Local.Path = resolvePath(cfg.Storage.Local.Path)
	cfg.Database.Path = resolvePath(cfg.Database.Path)

	return cfg, nil
}

// defaultStoragePath returns the absolute path used for file storage when
// no path is provided in the config file.
func defaultStoragePath() string {
	return resolvePath("./docops-data/files")
}

// defaultDBPath returns the absolute path used for the SQLite database when
// no path is provided in the config file.
func defaultDBPath() string {
	return resolvePath("./docops-data/docops.db")
}

// resolvePath converts a relative path to an absolute one anchored at the
// process working directory, then cleans any redundant separators or dot segments.
//
// Absolute paths are returned unchanged — this makes the function safe to call
// on paths that may already be absolute (e.g. from a previous resolvePath call
// or a user-supplied /etc/... path).
//
// On the rare occasion filepath.Abs fails (e.g. the working directory has been
// deleted), the original path is returned as-is rather than propagating an error,
// since this is a best-effort helper used only during startup.
func resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}

	abs, err := filepath.Abs(p)
	if err != nil {
		// Degraded fallback: return the original relative path.
		// Callers that require a guaranteed absolute path should check
		// filepath.IsAbs on the returned value.
		return p
	}
	return filepath.Clean(abs)
}

// config wraps models.Config to attach behaviour (Parse) without modifying the model.
type config struct {
	models.Config
}

// Parse is the public entry point that converts a raw *models.Config (from Load)
// into a fully typed *ParsedConfig ready for use by the application.
// It delegates to the private config.Parse method, keeping the implementation
// in one place while exposing a clean function signature to callers.
func Parse(raw *models.Config) (*ParsedConfig, error) {
	c := &config{Config: *raw}
	return c.Parse()
}

// ParsedConfig holds all configuration values in their final Go types,
// ready for direct use by the application without further parsing.
// Duration strings from the YAML/defaults are converted to time.Duration here;
// secrets are pulled from the environment rather than the config file so they
// are never accidentally committed to version control.
type ParsedConfig struct {
	Port                int
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	JWTSecret           []byte // loaded from JWT_SECRET env var — never from the YAML file
	StoragePath         string
	DatabasePath        string
	Argon2              models.Argon2Config
	RateLimitLimit      int
	RateLimitWindow     time.Duration
	RateLimitTrustProxy bool

	DocsRateLimitLimit  int
	DocsRateLimitWindow time.Duration
}

// Parse converts the raw string values in the config into typed Go values
// and merges in secrets from the environment.
//
// Environment loading (.env file):
//
//	godotenv.Load is called as a convenience for local development — it reads
//	a .env file if one exists and sets any variables not already present in
//	the environment. In production, variables should be injected directly into
//	the process environment (e.g. via Docker, systemd, or a secrets manager)
//	rather than through a .env file; godotenv.Load is a no-op when the file
//	is absent, so this is safe in both contexts.
//
// JWT_SECRET must be set; Parse returns an error if it is missing or empty.
func (c *config) Parse() (*ParsedConfig, error) {
	// Load .env into the environment for local development convenience.
	// Silently ignored if the file does not exist — production environments
	// are expected to inject secrets directly into the process environment.
	_ = godotenv.Load()

	// JWT_SECRET must be provided via environment — it should never appear
	// in the YAML file to avoid accidental exposure in version control.
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is not set")
	}

	accessTTL, err := time.ParseDuration(c.Auth.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid access_token_ttl %q: %w", c.Auth.AccessTokenTTL, err)
	}

	refreshTTL, err := time.ParseDuration(c.Auth.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh_token_ttl %q: %w", c.Auth.RefreshTokenTTL, err)
	}

	readTimeout, err := time.ParseDuration(c.Server.ReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid read_timeout %q: %w", c.Server.ReadTimeout, err)
	}

	writeTimeout, err := time.ParseDuration(c.Server.WriteTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid write_timeout %q: %w", c.Server.WriteTimeout, err)
	}

	limitWindow, err := time.ParseDuration(c.RateLimit.Window)
	if err != nil {
		return nil, fmt.Errorf("invalid rate_limit window %q: %w", c.RateLimit.Window, err)
	}

	docsWindow := limitWindow
	if c.RateLimit.Documents.Window != "" {
		docsWindow, err = time.ParseDuration(c.RateLimit.Documents.Window)
		if err != nil {
			return nil, fmt.Errorf("invalid rate_limit.documents window %q: %w", c.RateLimit.Documents.Window, err)
		}
	}
	docsLimit := c.RateLimit.Documents.Limit
	if docsLimit == 0 {
		docsLimit = c.RateLimit.Limit // zero → inherit the auth ceiling
	}

	return &ParsedConfig{
		Port:                c.Server.Port,
		ReadTimeout:         readTimeout,
		WriteTimeout:        writeTimeout,
		AccessTokenTTL:      accessTTL,
		RefreshTokenTTL:     refreshTTL,
		JWTSecret:           []byte(jwtSecret), // converted to []byte for direct use with JWT signing
		StoragePath:         c.Storage.Local.Path,
		DatabasePath:        c.Database.Path,
		Argon2:              c.Argon2,
		RateLimitLimit:      c.RateLimit.Limit,
		RateLimitWindow:     limitWindow,
		RateLimitTrustProxy: c.RateLimit.TrustProxyHeaders,

		DocsRateLimitLimit:  docsLimit,
		DocsRateLimitWindow: docsWindow,
	}, nil
}
