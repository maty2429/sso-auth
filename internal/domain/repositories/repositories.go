package repositories

import (
	"context"
	"time"

	"authserver/internal/domain/entities"
)

type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	GetByID(ctx context.Context, id string) (*entities.User, error)
	Save(ctx context.Context, user *entities.User) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *entities.Session) error
	Revoke(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (*entities.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]entities.Session, error)
}

type RefreshTokenRepository interface {
	Save(ctx context.Context, token string, sessionID string, expiresAt int64) error
	Delete(ctx context.Context, token string) error
	DeleteByUser(ctx context.Context, userID string) error
}

type AuditLogRepository interface {
	Record(ctx context.Context, userID string, action string, metadata map[string]any) error
}

type AuthClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*entities.AuthClient, error)
}

type CredentialRepository interface {
	GetByUserID(ctx context.Context, userID string) (*entities.User, error)
	UpdatePassword(ctx context.Context, userID, hash, algo string) error
	IncrementFailedAttempts(ctx context.Context, userID string) error
	ResetFailedAttempts(ctx context.Context, userID string) error
	SetLockedUntil(ctx context.Context, userID string, until *time.Time) error
}
