package repository

import (
	"context"
	"errors"

	"sso/internal/adapters/repository/dbrepo"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (r *PostgresRepo) GetMemberRole(ctx context.Context, userID string, projectCode string) (int, string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, "", err
	}

	params := dbrepo.GetProjectMemberParams{
		UserID:      pgtype.UUID{Bytes: uid, Valid: true},
		ProjectCode: projectCode,
	}

	row, err := r.Q.GetProjectMember(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", nil // Or specific error like ErrNotFound
		}
		return 0, "", err
	}

	return int(row.RoleCode), row.RoleName, nil
}
