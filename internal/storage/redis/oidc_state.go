package redisstore

import (
	"context"
	"time"

	"authserver/internal/domain/repositories"
	"github.com/redis/go-redis/v9"
)

type OIDCStateRepository struct {
	client *redis.Client
}

func NewOIDCStateRepository(client *redis.Client) repositories.OIDCStateRepository {
	return &OIDCStateRepository{client: client}
}

func (r *OIDCStateRepository) SaveState(ctx context.Context, state string, data string, ttlSeconds int64) error {
	return r.save(ctx, "oidc:state:"+state, data, ttlSeconds)
}

func (r *OIDCStateRepository) GetState(ctx context.Context, state string) (string, error) {
	return r.get(ctx, "oidc:state:"+state)
}

func (r *OIDCStateRepository) DeleteState(ctx context.Context, state string) error {
	return r.delete(ctx, "oidc:state:"+state)
}

func (r *OIDCStateRepository) SaveNonce(ctx context.Context, nonce string, ttlSeconds int64) error {
	return r.save(ctx, "oidc:nonce:"+nonce, "1", ttlSeconds)
}

func (r *OIDCStateRepository) ValidateNonce(ctx context.Context, nonce string) (bool, error) {
	val, err := r.client.Exists(ctx, "oidc:nonce:"+nonce).Result()
	if err != nil {
		return false, err
	}
	return val == 1, nil
}

func (r *OIDCStateRepository) DeleteNonce(ctx context.Context, nonce string) error {
	return r.delete(ctx, "oidc:nonce:"+nonce)
}

func (r *OIDCStateRepository) SavePKCE(ctx context.Context, codeVerifier string, codeChallenge string, ttlSeconds int64) error {
	return r.save(ctx, "oidc:pkce:"+codeVerifier, codeChallenge, ttlSeconds)
}

func (r *OIDCStateRepository) GetPKCE(ctx context.Context, codeVerifier string) (string, error) {
	return r.get(ctx, "oidc:pkce:"+codeVerifier)
}

func (r *OIDCStateRepository) DeletePKCE(ctx context.Context, codeVerifier string) error {
	return r.delete(ctx, "oidc:pkce:"+codeVerifier)
}

func (r *OIDCStateRepository) save(ctx context.Context, key, value string, ttlSeconds int64) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = 5 * time.Minute
	}
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *OIDCStateRepository) get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *OIDCStateRepository) delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
