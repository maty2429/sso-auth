package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RoleRepository struct {
	pool *pgxpool.Pool
}

func NewRoleRepository(pool *pgxpool.Pool) repositories.RoleRepository {
	return &RoleRepository{pool: pool}
}

func (r *RoleRepository) GetRolesByUser(ctx context.Context, userID string) ([]entities.Role, error) {
	const q = `
SELECT r.id, r.name, r.description, r.created_at
FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get roles by user: %w", err)
	}
	defer rows.Close()

	var roles []entities.Role
	for rows.Next() {
		var ro entities.Role
		if err := rows.Scan(&ro.ID, &ro.Name, &ro.Description, &ro.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, ro)
	}
	return roles, nil
}
