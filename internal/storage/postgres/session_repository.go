package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) repositories.SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, session *entities.Session) error {
	const q = `
INSERT INTO sessions (id, user_id, auth_client_id, device_info, ip_address, created_at, expires_at, is_revoked)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
`
	_, err := r.pool.Exec(ctx, q, session.ID, session.UserID, session.ClientID, session.DeviceInfo, session.IP, session.CreatedAt, session.ExpiresAt, session.Revoked)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	const q = `UPDATE sessions SET is_revoked = TRUE WHERE id = $1`
	if _, err := r.pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (*entities.Session, error) {
	const q = `
SELECT id, user_id, auth_client_id, device_info, ip_address, created_at, expires_at, is_revoked
FROM sessions WHERE id = $1
`
	var s entities.Session
	if err := r.pool.QueryRow(ctx, q, id).Scan(
		&s.ID, &s.UserID, &s.ClientID, &s.DeviceInfo, &s.IP, &s.CreatedAt, &s.ExpiresAt, &s.Revoked,
	); err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return &s, nil
}

func (r *SessionRepository) ListActiveByUser(ctx context.Context, userID string) ([]entities.Session, error) {
	const q = `
SELECT id, user_id, auth_client_id, device_info, ip_address, created_at, expires_at, is_revoked
FROM sessions
WHERE user_id = $1 AND is_revoked = FALSE AND expires_at > NOW()
ORDER BY created_at DESC
`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []entities.Session
	for rows.Next() {
		var s entities.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.ClientID, &s.DeviceInfo, &s.IP, &s.CreatedAt, &s.ExpiresAt, &s.Revoked); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}
