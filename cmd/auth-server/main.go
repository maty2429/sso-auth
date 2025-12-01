package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authserver/internal/config"
	"authserver/internal/domain/repositories"
	"authserver/internal/domain/services"
	httpserver "authserver/internal/handlers/http"
	"authserver/internal/security/hash"
	"authserver/internal/security/jwt"
	"authserver/internal/security/ratelimit"
	"authserver/internal/storage/postgres"
	redisstore "authserver/internal/storage/redis"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load config")
	}

	ctx := context.Background()
	var redisClient *redis.Client
	if cfg.Redis.Addr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
	}

	pool, err := postgres.Connect(ctx, cfg.Database)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect postgres")
	}
	defer pool.Close()

	userRepo := postgres.NewUserRepository(pool)
	sessionRepo := postgres.NewSessionRepository(pool)
	refreshRepo := postgres.NewRefreshTokenRepository(pool)
	clientRepo := postgres.NewAuthClientRepository(pool)
	_ = postgres.NewCredentialRepository(pool) // reserved for future use
	auditRepo := postgres.NewAuditRepository(pool)
	roleRepo := postgres.NewRoleRepository(pool)
	projectRepo := postgres.NewProjectRepository(pool)

	hasher := hash.NewArgon2(cfg.Argon2.Memory, cfg.Argon2.Iterations, cfg.Argon2.Parallelism, cfg.Argon2.SaltLength, cfg.Argon2.KeyLength)
	tokenProvider := jwt.NewProvider(&cfg.JWT)

	var deviceSec services.DeviceSecurity
	var userLock services.UserTempLock
	var limiter ratelimit.Middleware
	if redisClient != nil {
		if l, err := ratelimit.New(cfg.Limiter, cfg.Redis, logger); err != nil {
			logger.Warn().Err(err).Msg("rate limiter not initialized")
		} else {
			limiter = l
		}
		deviceSec = redisstore.NewDeviceSecurityRepository(redisClient)
		userLock = redisstore.NewUserTempLockRepository(redisClient)
	}

	var blacklistRepo repositories.TokenBlacklistRepository
	var oidcRepo repositories.OIDCStateRepository
	if redisClient != nil {
		blacklistRepo = redisstore.NewTokenBlacklistRepository(redisClient)
		oidcRepo = redisstore.NewOIDCStateRepository(redisClient)
	}

	auditService := services.NewAuditService(auditRepo)
	sessionService := services.NewSessionService(sessionRepo, refreshRepo, blacklistRepo, auditService)

	authService := services.NewAuthService(
		userRepo,
		sessionRepo,
		refreshRepo,
		blacklistRepo,
		roleRepo,
		projectRepo,
		userLock,
		deviceSec,
		auditService,
		services.SecuritySettings{
			MaxDeviceAttempts:  cfg.Security.MaxDeviceAttempts,
			DeviceBlockSeconds: cfg.Security.DeviceBlockSeconds,
			UserLockSeconds:    cfg.Security.UserLockSeconds,
		},
		hasher,
		tokenProvider,
		limiter,
		logger,
	)

	server := httpserver.NewServer(cfg, logger, httpserver.Dependencies{
		AuthService: authService,
		Limiter:     limiter,
		Tokens:      tokenProvider,
		Blacklist:   blacklistRepo,
		OIDCRepo:    oidcRepo,
		ClientRepo:  clientRepo,
		OIDCConfig:  &cfg.OIDC,
		SessionSvc:  sessionService,
	})

	go func() {
		if err := server.Start(); err != nil {
			logger.Fatal().Err(err).Msg("http server stopped unexpectedly")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
