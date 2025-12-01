package postgres

import (
	"context"
	"fmt"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthClientRepository struct {
	pool *pgxpool.Pool
}

func NewAuthClientRepository(pool *pgxpool.Pool) repositories.AuthClientRepository {
	return &AuthClientRepository{pool: pool}
}

func (r *AuthClientRepository) GetByClientID(ctx context.Context, clientID string) (*entities.AuthClient, error) {
	const q = `
SELECT id, client_id, client_name, client_secret, is_confidential, allowed_grants, redirect_uris, is_active
FROM auth_clients
WHERE client_id = $1
`
	var ac entities.AuthClient
	if err := r.pool.QueryRow(ctx, q, clientID).Scan(
		&ac.ID,
		&ac.ClientID,
		&ac.ClientName,
		&ac.ClientSecret,
		&ac.IsConfidential,
		&ac.AllowedGrants,
		&ac.RedirectURIs,
		&ac.IsActive,
	); err != nil {
		return nil, fmt.Errorf("get auth client: %w", err)
	}
	return &ac, nil
}
