package ports

import (
	"context"

	"sso/internal/core/domain"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (string, string, error) // Returns access_token, refresh_token, error
	Register(ctx context.Context, user *domain.User, password string) (*domain.User, error)
	ValidateToken(tokenString string) (*domain.User, error)
}
