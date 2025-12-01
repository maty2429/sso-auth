package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditRepository struct {
	pool *pgxpool.Pool
}

func NewAuditRepository(pool *pgxpool.Pool) repositories.AuditLogRepository {
	return &AuditRepository{pool: pool}
}

func (r *AuditRepository) Record(ctx context.Context, userID string, action string, metadata map[string]any) error {
	const q = `
INSERT INTO audit_logs (user_id, action, description, created_at)
VALUES ($1, $2, $3, NOW())
`
	_, err := r.pool.Exec(ctx, q, nullable(userID), action, fmt.Sprintf("%v", metadata))
	if err != nil {
		return fmt.Errorf("audit record: %w", err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
