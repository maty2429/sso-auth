package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type RateLimitRepository struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRateLimitRepository(client *redis.Client, ttl time.Duration) repositories.RateLimitRepository {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &RateLimitRepository{client: client, ttl: ttl}
}

func (r *RateLimitRepository) IncrementUserAttempts(ctx context.Context, userID string) (int, error) {
	return r.increment(ctx, "ratelimit:user:"+userID)
}

func (r *RateLimitRepository) IncrementIPAttempts(ctx context.Context, ip string) (int, error) {
	return r.increment(ctx, "ratelimit:ip:"+ip)
}

func (r *RateLimitRepository) IncrementRUTAttempts(ctx context.Context, rut string) (int, error) {
	return r.increment(ctx, "ratelimit:rut:"+rut)
}

func (r *RateLimitRepository) IncrementDeviceAttempts(ctx context.Context, deviceID string) (int, error) {
	return r.increment(ctx, "ratelimit:device:"+deviceID)
}

func (r *RateLimitRepository) ResetUserAttempts(ctx context.Context, userID string) error {
	return r.reset(ctx, "ratelimit:user:"+userID)
}

func (r *RateLimitRepository) ResetIPAttempts(ctx context.Context, ip string) error {
	return r.reset(ctx, "ratelimit:ip:"+ip)
}

func (r *RateLimitRepository) ResetRUTAttempts(ctx context.Context, rut string) error {
	return r.reset(ctx, "ratelimit:rut:"+rut)
}

func (r *RateLimitRepository) ResetDeviceAttempts(ctx context.Context, deviceID string) error {
	return r.reset(ctx, "ratelimit:device:"+deviceID)
}

func (r *RateLimitRepository) increment(ctx context.Context, key string) (int, error) {
	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if val == 1 {
		_ = r.client.Expire(ctx, key, r.ttl).Err()
	}
	return int(val), nil
}

func (r *RateLimitRepository) reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
