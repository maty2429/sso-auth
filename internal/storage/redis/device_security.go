package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type DeviceSecurityRepository struct {
	client *redis.Client
}

func NewDeviceSecurityRepository(client *redis.Client) repositories.DeviceSecurityRepository {
	return &DeviceSecurityRepository{client: client}
}

func (r *DeviceSecurityRepository) IncrementAttempts(ctx context.Context, deviceID string) (int, error) {
	key := "device:" + deviceID + ":attempts"
	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if val == 1 {
		_ = r.client.Expire(ctx, key, time.Hour).Err()
	}
	return int(val), nil
}

func (r *DeviceSecurityRepository) ResetAttempts(ctx context.Context, deviceID string) error {
	return r.client.Del(ctx, "device:"+deviceID+":attempts").Err()
}

func (r *DeviceSecurityRepository) IsBlocked(ctx context.Context, deviceID string) (bool, error) {
	return r.exists(ctx, "device:"+deviceID+":blocked")
}

func (r *DeviceSecurityRepository) BlockDevice(ctx context.Context, deviceID string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 10 * time.Minute
	}
	return r.client.Set(ctx, "device:"+deviceID+":blocked", "1", ttl).Err()
}

func (r *DeviceSecurityRepository) SaveFingerprint(ctx context.Context, deviceID string, payload string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 24 * time.Hour
	}
	return r.client.Set(ctx, "device:"+deviceID+":fingerprint", payload, ttl).Err()
}

func (r *DeviceSecurityRepository) GetFingerprint(ctx context.Context, deviceID string) (string, error) {
	return r.client.Get(ctx, "device:"+deviceID+":fingerprint").Result()
}

func (r *DeviceSecurityRepository) exists(ctx context.Context, key string) (bool, error) {
	res, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}
