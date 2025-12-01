package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type RecoveryRepository struct {
	client *redis.Client
}

func NewRecoveryRepository(client *redis.Client) repositories.RecoveryRepository {
	return &RecoveryRepository{client: client}
}

func (r *RecoveryRepository) SavePasswordResetToken(ctx context.Context, token string, userID string, ttlSeconds int64) error {
	return r.save(ctx, "reset:password:"+token, userID, ttlSeconds)
}

func (r *RecoveryRepository) GetUserIDByPasswordResetToken(ctx context.Context, token string) (string, error) {
	return r.client.Get(ctx, "reset:password:"+token).Result()
}

func (r *RecoveryRepository) DeletePasswordResetToken(ctx context.Context, token string) error {
	return r.client.Del(ctx, "reset:password:"+token).Err()
}

func (r *RecoveryRepository) SaveEmailVerification(ctx context.Context, token string, userID string, ttlSeconds int64) error {
	return r.save(ctx, "email:verify:"+token, userID, ttlSeconds)
}

func (r *RecoveryRepository) GetEmailVerification(ctx context.Context, token string) (string, error) {
	return r.client.Get(ctx, "email:verify:"+token).Result()
}

func (r *RecoveryRepository) DeleteEmailVerification(ctx context.Context, token string) error {
	return r.client.Del(ctx, "email:verify:"+token).Err()
}

func (r *RecoveryRepository) save(ctx context.Context, key, value string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 15 * time.Minute
	}
	return r.client.Set(ctx, key, value, ttl).Err()
}
