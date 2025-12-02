package repository

import (
	"sso/internal/adapters/repository/dbrepo"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepo struct {
	DB *pgxpool.Pool
	Q  dbrepo.Querier
}

func NewPostgresRepo(db *pgxpool.Pool) *PostgresRepo {
	return &PostgresRepo{
		DB: db,
		Q:  dbrepo.New(db),
	}
}
