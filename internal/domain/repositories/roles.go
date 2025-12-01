package repositories

import (
	"context"

	"authserver/internal/domain/entities"
)

type RoleRepository interface {
	GetRolesByUser(ctx context.Context, userID string) ([]entities.Role, error)
}
