package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"authserver/internal/domain/repositories"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) repositories.RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

func (r *RefreshTokenRepository) Save(ctx context.Context, token string, sessionID string, expiresAt int64) error {
	hash := sha256.Sum256([]byte(token))
	const q = `
INSERT INTO refresh_tokens (user_id, session_id, token_hash, expires_at)
SELECT s.user_id, $1, $2, to_timestamp($3)
FROM sessions s
WHERE s.id = $1
ON CONFLICT DO NOTHING
`
	_, err := r.pool.Exec(ctx, q, sessionID, hex.EncodeToString(hash[:]), expiresAt)
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) Delete(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	const q = `UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_hash = $1`
	if _, err := r.pool.Exec(ctx, q, hex.EncodeToString(hash[:])); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) DeleteByUser(ctx context.Context, userID string) error {
	const q = `UPDATE refresh_tokens SET is_revoked = TRUE WHERE user_id = $1`
	if _, err := r.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens by user: %w", err)
	}
	return nil
}
