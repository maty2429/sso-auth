package repository

import (
	"context"
	"net/netip"

	"sso/internal/adapters/repository/dbrepo"
	"sso/internal/core/domain"

	"github.com/jackc/pgx/v5/pgtype"
)

func (r *PostgresRepo) SaveRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	var ip *netip.Addr
	if t.IPAddress != "" {
		parsedIP, err := netip.ParseAddr(t.IPAddress)
		if err == nil {
			ip = &parsedIP
		}
	}

	params := dbrepo.CreateRefreshTokenParams{
		UserID:     pgtype.UUID{Bytes: t.UserID, Valid: true},
		TokenHash:  t.TokenHash,
		DeviceInfo: pgtype.Text{String: t.DeviceInfo, Valid: t.DeviceInfo != ""},
		IpAddress:  ip,
		ExpiresAt:  pgtype.Timestamp{Time: t.ExpiresAt, Valid: true},
	}

	_, err := r.Q.CreateRefreshToken(ctx, params)
	return err
}
