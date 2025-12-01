package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type TokenBlacklistRepository struct {
	client *redis.Client
}

func NewTokenBlacklistRepository(client *redis.Client) repositories.TokenBlacklistRepository {
	return &TokenBlacklistRepository{client: client}
}

func (r *TokenBlacklistRepository) BlacklistAccessToken(ctx context.Context, jti string, ttlSeconds int64) error {
	return r.setWithTTL(ctx, "blacklist:access:"+jti, ttlSeconds)
}

func (r *TokenBlacklistRepository) BlacklistRefreshToken(ctx context.Context, jti string, ttlSeconds int64) error {
	return r.setWithTTL(ctx, "blacklist:refresh:"+jti, ttlSeconds)
}

func (r *TokenBlacklistRepository) BlacklistSession(ctx context.Context, sessionID string, ttlSeconds int64) error {
	return r.setWithTTL(ctx, "blacklist:session:"+sessionID, ttlSeconds)
}

func (r *TokenBlacklistRepository) BlacklistUser(ctx context.Context, userID string, ttlSeconds int64) error {
	return r.setWithTTL(ctx, "blacklist:user:"+userID, ttlSeconds)
}

func (r *TokenBlacklistRepository) IsAccessTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	return r.exists(ctx, "blacklist:access:"+jti)
}

func (r *TokenBlacklistRepository) IsRefreshTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	return r.exists(ctx, "blacklist:refresh:"+jti)
}

func (r *TokenBlacklistRepository) IsSessionBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	return r.exists(ctx, "blacklist:session:"+sessionID)
}

func (r *TokenBlacklistRepository) IsUserBlacklisted(ctx context.Context, userID string) (bool, error) {
	return r.exists(ctx, "blacklist:user:"+userID)
}

func (r *TokenBlacklistRepository) setWithTTL(ctx context.Context, key string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 0
	}
	return r.client.Set(ctx, key, "1", ttl).Err()
}

func (r *TokenBlacklistRepository) exists(ctx context.Context, key string) (bool, error) {
	res, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}
