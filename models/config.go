package models

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Storage   StorageConfig   `yaml:"storage"`
	Auth      AuthConfig      `yaml:"auth"`
	Database  DatabaseConfig  `yaml:"database"`
	Argon2    Argon2Config    `yaml:"argon2"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type RateLimitConfig struct {
	Limit  int    `yaml:"limit"`
	Window string `yaml:"window"`

	// TrustProxyHeaders controls whether X-Forwarded-For / X-Real-IP are
	// honored when deriving the client IP for rate limiting. Defaults to
	// false: these headers are client-controlled and trivially spoofable,
	// so enabling them on a directly-exposed server lets attackers rotate
	// their identity per request and bypass the limit entirely (or poison
	// a victim IP into 429s). Enable ONLY behind a proxy that sanitizes
	// or overwrites these headers itself.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`

	// Documents bounds the document routes (upload/download/search/delete).
	// These endpoints serve machine traffic far more frequently than auth
	// endpoints, so they carry their own, higher ceiling. Zero falls back
	// to the auth limit during Parse.
	Documents RateLimitSubConfig `yaml:"documents"`
}

type RateLimitSubConfig struct {
	Limit  int    `yaml:"limit"`
	Window string `yaml:"window"`
}

type ServerConfig struct {
	Port         int    `yaml:"port"`
	ReadTimeout  string `yaml:"read_timeout"`
	WriteTimeout string `yaml:"write_timeout"`
}

type AuthConfig struct {
	AccessTokenTTL  string `yaml:"access_token_ttl"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`
}

type Argon2Config struct {
	Memory      uint32 `yaml:"memory"`
	Iterations  uint32 `yaml:"iterations"`
	Parallelism uint8  `yaml:"parallelism"`
	KeyLength   uint32 `yaml:"key_length"`
	SaltLength  uint32 `yaml:"salt_length"`
}

type StorageConfig struct {
	Local LocalStorageConfig `yaml:"local"`
}

type LocalStorageConfig struct {
	Path string `yaml:"path"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}
