package domain

import (
	"time"

	"github.com/google/uuid"
)

type Project struct {
	ID          int
	ProjectCode string
	Name        string
	Description string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ProjectMember struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ProjectID int
	RoleCode  int
	IsActive  bool
	JoinedAt  time.Time
}

type Role struct {
	Code        int
	Name        string
	Description string
}
