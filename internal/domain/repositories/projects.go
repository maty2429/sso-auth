package repositories

import (
	"context"

	"authserver/internal/domain/entities"
)

type ProjectRepository interface {
	GetProjectsByUser(ctx context.Context, userID string) ([]entities.Project, error)
}
