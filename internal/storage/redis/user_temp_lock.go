package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type UserTempLockRepository struct {
	client *redis.Client
}

func NewUserTempLockRepository(client *redis.Client) repositories.UserTempLockRepository {
	return &UserTempLockRepository{client: client}
}

func (r *UserTempLockRepository) LockUser(ctx context.Context, userID string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 10 * time.Minute
	}
	return r.client.Set(ctx, "user:"+userID+":temp_locked", "1", ttl).Err()
}

func (r *UserTempLockRepository) IsUserLocked(ctx context.Context, userID string) (bool, error) {
	res, err := r.client.Exists(ctx, "user:"+userID+":temp_locked").Result()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (r *UserTempLockRepository) UnlockUser(ctx context.Context, userID string) error {
	return r.client.Del(ctx, "user:"+userID+":temp_locked").Err()
}
