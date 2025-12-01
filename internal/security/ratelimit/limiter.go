package ratelimit

import (
	"context"
	"fmt"
	"net/http"

	"authserver/internal/config"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/ulule/limiter/v3"
	limiterredis "github.com/ulule/limiter/v3/drivers/store/redis"
)

type Middleware interface {
	HTTP(next http.Handler) http.Handler
	Allow(ctx context.Context, key string) error
}

type Limiter struct {
	lim    *limiter.Limiter
	logger zerolog.Logger
}

func New(cfg config.LimiterConfig, redisCfg config.RedisConfig, logger zerolog.Logger) (Middleware, error) {
	store, err := limiterredis.NewStoreWithOptions(redis.NewClient(&redis.Options{
		Addr:     redisCfg.Addr,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	}), limiter.StoreOptions{
		Prefix: "auth_rate_limit",
	})
	if err != nil {
		return nil, err
	}

	rate := limiter.Rate{
		Period: cfg.Window,
		Limit:  int64(cfg.Requests),
	}
	return &Limiter{
		lim:    limiter.New(store, rate),
		logger: logger,
	}, nil
}

func (l *Limiter) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		context, err := l.lim.Get(r.Context(), key)
		if err != nil {
			l.logger.Error().Err(err).Msg("rate limit failure")
			http.Error(w, "rate limit error", http.StatusInternalServerError)
			return
		}
		w.Header().Add("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
		w.Header().Add("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
		w.Header().Add("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))
		if context.Reached {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) Allow(ctx context.Context, key string) error {
	res, err := l.lim.Peek(ctx, key)
	if err != nil {
		return err
	}
	if res.Reached {
		return fmt.Errorf("too many requests")
	}
	return nil
}
