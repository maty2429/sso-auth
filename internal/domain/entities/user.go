package entities

import "time"

type User struct {
	ID           string
	RUT          string
	DV           string
	FirstName    string
	LastName     string
	Email        string
	Phone        string
	PasswordHash string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Role struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

type Project struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

type AuthClient struct {
	ID             string
	ClientID       string
	ClientName     string
	ClientSecret   string
	IsConfidential bool
	AllowedGrants  []string
	RedirectURIs   []string
	IsActive       bool
}

type Session struct {
	ID         string
	UserID     string
	ClientID   string
	IP         string
	UserAgent  string
	DeviceInfo map[string]any
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Revoked    bool
	RevokedAt  *time.Time
}
