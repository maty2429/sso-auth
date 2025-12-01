package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProjectRepository struct {
	pool *pgxpool.Pool
}

func NewProjectRepository(pool *pgxpool.Pool) repositories.ProjectRepository {
	return &ProjectRepository{pool: pool}
}

func (r *ProjectRepository) GetProjectsByUser(ctx context.Context, userID string) ([]entities.Project, error) {
	const q = `
SELECT p.id, p.name, p.description, p.created_at
FROM projects p
JOIN user_projects up ON up.project_id = p.id
WHERE up.user_id = $1
`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get projects by user: %w", err)
	}
	defer rows.Close()

	var projects []entities.Project
	for rows.Next() {
		var p entities.Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		projects = append(projects, p)
	}
	return projects, nil
}
