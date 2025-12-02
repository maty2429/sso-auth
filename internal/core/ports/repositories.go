package ports

import (
	"context"

	"sso/internal/core/domain"
)

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByRut(ctx context.Context, rut int) (*domain.User, error)
}

type TokenRepository interface {
	SaveRefreshToken(ctx context.Context, token *domain.RefreshToken) error
}

type ProjectRepository interface {
	GetMemberRole(ctx context.Context, userID string, projectCode string) (int, string, error)
}
