package repository

import (
	"context"
	"errors"

	"sso/internal/adapters/repository/dbrepo"
	"sso/internal/core/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *PostgresRepo) Save(ctx context.Context, u *domain.User) (*domain.User, error) {
	params := dbrepo.CreateUserParams{
		Rut:          int32(u.Rut),
		Dv:           u.Dv,
		Email:        u.Email,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		PasswordHash: u.PasswordHash,
	}

	row, err := r.Q.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	return mapUser(row), nil
}

func (r *PostgresRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.Q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return mapUser(row), nil
}

func (r *PostgresRepo) FindByRut(ctx context.Context, rut int) (*domain.User, error) {
	row, err := r.Q.GetUserByRut(ctx, int32(rut))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return mapUser(row), nil
}

func mapUser(row dbrepo.User) *domain.User {
	var id uuid.UUID
	if row.ID.Valid {
		id = row.ID.Bytes
	}

	return &domain.User{
		ID:           id,
		Rut:          int(row.Rut),
		Dv:           row.Dv,
		Email:        row.Email,
		FirstName:    row.FirstName,
		LastName:     row.LastName,
		PasswordHash: row.PasswordHash,
		IsActive:     row.IsActive.Bool,
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
	}
}
