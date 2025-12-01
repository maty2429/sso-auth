package postgres

import (
	"context"
	"fmt"
	"time"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CredentialRepository struct {
	pool *pgxpool.Pool
}

func NewCredentialRepository(pool *pgxpool.Pool) repositories.CredentialRepository {
	return &CredentialRepository{pool: pool}
}

func (r *CredentialRepository) GetByUserID(ctx context.Context, userID string) (*entities.User, error) {
	const q = `
SELECT u.id, u.rut, u.dv, u.first_name, u.last_name, u.email, u.phone, u.is_active, u.created_at, u.updated_at,
       uc.password_hash
FROM users u
JOIN user_credentials uc ON uc.user_id = u.id
WHERE u.id = $1
`
	var u entities.User
	if err := r.pool.QueryRow(ctx, q, userID).Scan(
		&u.ID, &u.RUT, &u.DV, &u.FirstName, &u.LastName, &u.Email, &u.Phone, &u.IsActive, &u.CreatedAt, &u.UpdatedAt, &u.PasswordHash,
	); err != nil {
		return nil, fmt.Errorf("credential by user: %w", err)
	}
	return &u, nil
}

func (r *CredentialRepository) UpdatePassword(ctx context.Context, userID, hash, algo string) error {
	const q = `
UPDATE user_credentials
SET password_hash = $2, password_algo = $3, last_password_change = NOW(), failed_attempts = 0, locked_until = NULL, must_change_password = FALSE
WHERE user_id = $1
`
	if _, err := r.pool.Exec(ctx, q, userID, hash, algo); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

func (r *CredentialRepository) IncrementFailedAttempts(ctx context.Context, userID string) error {
	const q = `UPDATE user_credentials SET failed_attempts = failed_attempts + 1 WHERE user_id = $1`
	if _, err := r.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("increment attempts: %w", err)
	}
	return nil
}

func (r *CredentialRepository) ResetFailedAttempts(ctx context.Context, userID string) error {
	const q = `UPDATE user_credentials SET failed_attempts = 0 WHERE user_id = $1`
	if _, err := r.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("reset attempts: %w", err)
	}
	return nil
}

func (r *CredentialRepository) SetLockedUntil(ctx context.Context, userID string, until *time.Time) error {
	const q = `UPDATE user_credentials SET locked_until = $2 WHERE user_id = $1`
	if _, err := r.pool.Exec(ctx, q, userID, until); err != nil {
		return fmt.Errorf("set locked_until: %w", err)
	}
	return nil
}
