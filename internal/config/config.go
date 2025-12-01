package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Config aggregates runtime configuration loaded via viper.
type Config struct {
	App      AppConfig      `mapstructure:"app"`
	Server   ServerConfig   `mapstructure:"server"`
	Database DBConfig       `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Limiter  LimiterConfig  `mapstructure:"limiter"`
	Argon2   Argon2Config   `mapstructure:"argon2"`
	CORS     CORSConfig     `mapstructure:"cors"`
	Security SecurityConfig `mapstructure:"security"`
	OIDC     OIDCConfig     `mapstructure:"oidc"`
}

type AppConfig struct {
	Name string `mapstructure:"name"`
	Env  string `mapstructure:"env"`
	Port int    `mapstructure:"port"`
	URL  string `mapstructure:"url"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type DBConfig struct {
	URL            string        `mapstructure:"url"`
	MaxConnections int32         `mapstructure:"max_connections"`
	MaxConnIdle    time.Duration `mapstructure:"max_conn_idle"`
	MaxConnLife    time.Duration `mapstructure:"max_conn_life"`
}

type JWTConfig struct {
	AccessSecret     string        `mapstructure:"access_secret"`
	RefreshSecret    string        `mapstructure:"refresh_secret"`
	Issuer           string        `mapstructure:"issuer"`
	AccessTTLMinutes int           `mapstructure:"exp_minutes"`
	RefreshTTLDays   int           `mapstructure:"refresh_exp_days"`
	AllowedAud       []string      `mapstructure:"allowed_aud"`
	ClockSkew        time.Duration `mapstructure:"clock_skew"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type LimiterConfig struct {
	Requests   int           `mapstructure:"requests"`
	Window     time.Duration `mapstructure:"window"`
	Identifier string        `mapstructure:"identifier"`
}

type Argon2Config struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

type CORSConfig struct {
	AllowedOrigins   []string      `mapstructure:"allowed_origins"`
	AllowedMethods   []string      `mapstructure:"allowed_methods"`
	AllowedHeaders   []string      `mapstructure:"allowed_headers"`
	AllowCredentials bool          `mapstructure:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age"`
}

type SecurityConfig struct {
	MaxDeviceAttempts  int   `mapstructure:"max_device_attempts"`
	DeviceBlockSeconds int64 `mapstructure:"device_block_seconds"`
	UserLockSeconds    int64 `mapstructure:"user_lock_seconds"`
}

type OIDCConfig struct {
	AllowedRedirects []string `mapstructure:"allowed_redirects"`
}

// AccessTTL returns the computed duration from minutes.
func (j JWTConfig) AccessTTL() time.Duration {
	if j.AccessTTLMinutes <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(j.AccessTTLMinutes) * time.Minute
}

// RefreshTTL returns the computed duration from days.
func (j JWTConfig) RefreshTTL() time.Duration {
	if j.RefreshTTLDays <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(j.RefreshTTLDays) * 24 * time.Hour
}

// Load initializes viper and unmarshals configuration into Config.
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)
	bindEnvOverrides(v)

	if err := v.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("config file not found, relying on env/defaults")
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("app.name", "auth-server")
	v.SetDefault("app.env", "production")
	v.SetDefault("app.port", 8080)
	v.SetDefault("app.url", "https://auth.local")

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "10s")

	v.SetDefault("database.max_connections", 5)
	v.SetDefault("database.max_conn_idle", "30m")
	v.SetDefault("database.max_conn_life", "2h")

	v.SetDefault("jwt.exp_minutes", 15)
	v.SetDefault("jwt.refresh_exp_days", 30)
	v.SetDefault("jwt.issuer", "auth-server")
	v.SetDefault("jwt.clock_skew", "1m")

	v.SetDefault("limiter.requests", 5)
	v.SetDefault("limiter.window", "1m")
	v.SetDefault("limiter.identifier", "ip")

	v.SetDefault("argon2.memory", 65536)
	v.SetDefault("argon2.iterations", 1)
	v.SetDefault("argon2.parallelism", 2)
	v.SetDefault("argon2.salt_length", 16)
	v.SetDefault("argon2.key_length", 32)

	v.SetDefault("cors.allowed_origins", []string{"https://auth.local"})
	v.SetDefault("cors.allowed_methods", []string{"GET", "POST", "OPTIONS"})
	v.SetDefault("cors.allowed_headers", []string{"Authorization", "Content-Type", "X-Client-ID", "X-Request-ID"})
	v.SetDefault("cors.allow_credentials", true)
	v.SetDefault("cors.max_age", "10m")

	v.SetDefault("security.max_device_attempts", 5)
	v.SetDefault("security.device_block_seconds", 600)
	v.SetDefault("security.user_lock_seconds", 600)

	v.SetDefault("oidc.allowed_redirects", []string{"https://auth.local"})
}

func bindEnvOverrides(v *viper.Viper) {
	_ = v.BindEnv("app.env", "APP_ENV")
	_ = v.BindEnv("app.port", "APP_PORT")
	_ = v.BindEnv("app.url", "APP_URL")

	_ = v.BindEnv("database.url", "POSTGRES_DSN")

	_ = v.BindEnv("redis.addr", "REDIS_ADDR")
	_ = v.BindEnv("redis.password", "REDIS_PASS")
	_ = v.BindEnv("redis.db", "REDIS_DB")

	_ = v.BindEnv("jwt.access_secret", "JWT_ACCESS_SECRET")
	_ = v.BindEnv("jwt.refresh_secret", "JWT_REFRESH_SECRET")
	_ = v.BindEnv("jwt.issuer", "JWT_ISSUER")
	_ = v.BindEnv("jwt.exp_minutes", "JWT_EXP_MINUTES")
	_ = v.BindEnv("jwt.refresh_exp_days", "JWT_REFRESH_EXP_DAYS")

	_ = v.BindEnv("argon2.memory", "ARGON2_MEMORY")
	_ = v.BindEnv("argon2.iterations", "ARGON2_ITERATIONS")
	_ = v.BindEnv("argon2.parallelism", "ARGON2_PARALLELISM")
	_ = v.BindEnv("argon2.salt_length", "ARGON2_SALT_LENGTH")
	_ = v.BindEnv("argon2.key_length", "ARGON2_KEY_LENGTH")

	_ = v.BindEnv("security.max_device_attempts", "SECURITY_MAX_DEVICE_ATTEMPTS")
	_ = v.BindEnv("security.device_block_seconds", "SECURITY_DEVICE_BLOCK_SECONDS")
	_ = v.BindEnv("security.user_lock_seconds", "SECURITY_USER_LOCK_SECONDS")

	_ = v.BindEnv("oidc.allowed_redirects", "OIDC_ALLOWED_REDIRECTS")
}

// Validate ensures required fields are present and sensible.
func (c *Config) Validate() error {
	if c.App.Env == "" || c.App.URL == "" {
		return errors.New("config: app.env and app.url are required")
	}
	if c.App.Port <= 0 {
		return errors.New("config: app.port must be > 0")
	}
	if c.Server.Port == 0 {
		c.Server.Port = c.App.Port
	}
	if c.Database.URL == "" {
		return errors.New("config: database.url (POSTGRES_DSN) is required")
	}
	if c.JWT.AccessSecret == "" || c.JWT.RefreshSecret == "" {
		return errors.New("config: jwt access and refresh secrets are required")
	}
	if c.JWT.Issuer == "" {
		return errors.New("config: jwt issuer is required")
	}
	if c.Argon2.Memory == 0 || c.Argon2.Iterations == 0 || c.Argon2.Parallelism == 0 {
		return errors.New("config: argon2 parameters must be > 0")
	}
	if len(c.CORS.AllowedOrigins) == 0 {
		c.CORS.AllowedOrigins = []string{c.App.URL}
	}
	if c.Security.MaxDeviceAttempts <= 0 {
		c.Security.MaxDeviceAttempts = 5
	}
	if c.Security.DeviceBlockSeconds <= 0 {
		c.Security.DeviceBlockSeconds = 600
	}
	if c.Security.UserLockSeconds < 0 {
		c.Security.UserLockSeconds = 0
	}
	if len(c.OIDC.AllowedRedirects) == 0 {
		c.OIDC.AllowedRedirects = []string{c.App.URL}
	}
	return nil
}
