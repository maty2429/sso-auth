package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID
	Rut            int
	Dv             string
	Email          string
	FirstName      string
	LastName       string
	PasswordHash   string
	IsActive       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	DeviceInfo string
	IPAddress  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
