package models

type Config struct {
    Server   ServerConfig   `yaml:"server"`
    Storage  StorageConfig  `yaml:"storage"`
    Auth     AuthConfig     `yaml:"auth"`
    Database DatabaseConfig `yaml:"database"`
    Argon2   Argon2Config   `yaml:"argon2"`
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



