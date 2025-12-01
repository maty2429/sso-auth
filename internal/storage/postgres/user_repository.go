package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) repositories.UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	const q = `
SELECT u.id, u.rut, u.dv, u.first_name, u.last_name, u.email, u.phone, u.is_active, u.created_at, u.updated_at,
       uc.password_hash
FROM users u
JOIN user_credentials uc ON uc.user_id = u.id
WHERE u.email = $1
`
	var u entities.User
	if err := r.pool.QueryRow(ctx, q, email).Scan(
		&u.ID, &u.RUT, &u.DV, &u.FirstName, &u.LastName, &u.Email, &u.Phone, &u.IsActive, &u.CreatedAt, &u.UpdatedAt, &u.PasswordHash,
	); err != nil {
		return nil, fmt.Errorf("user by email: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*entities.User, error) {
	const q = `
SELECT u.id, u.rut, u.dv, u.first_name, u.last_name, u.email, u.phone, u.is_active, u.created_at, u.updated_at,
       uc.password_hash
FROM users u
JOIN user_credentials uc ON uc.user_id = u.id
WHERE u.id = $1
`
	var u entities.User
	if err := r.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.RUT, &u.DV, &u.FirstName, &u.LastName, &u.Email, &u.Phone, &u.IsActive, &u.CreatedAt, &u.UpdatedAt, &u.PasswordHash,
	); err != nil {
		return nil, fmt.Errorf("user by id: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) Save(ctx context.Context, user *entities.User) error {
	const q = `
INSERT INTO users (id, rut, dv, first_name, last_name, email, phone, is_active)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET
  rut = EXCLUDED.rut,
  dv = EXCLUDED.dv,
  first_name = EXCLUDED.first_name,
  last_name = EXCLUDED.last_name,
  email = EXCLUDED.email,
  phone = EXCLUDED.phone,
  is_active = EXCLUDED.is_active,
  updated_at = NOW()
`
	_, err := r.pool.Exec(ctx, q, user.ID, user.RUT, user.DV, user.FirstName, user.LastName, user.Email, user.Phone, user.IsActive)
	if err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}
