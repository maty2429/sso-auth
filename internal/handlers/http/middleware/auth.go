package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"authserver/internal/domain/repositories"
	"authserver/internal/domain/services"
	"authserver/internal/handlers/respond"
)

type contextKey string

const accessClaimsKey contextKey = "access_claims"

type NowFunc func() time.Time

type NowKey struct{}

// AuthMiddleware validates access tokens and checks blacklist.
type AuthMiddleware struct {
	tokens    services.TokenManager
	blacklist repositories.TokenBlacklistRepository
}

func NewAuthMiddleware(tokens services.TokenManager, blacklist repositories.TokenBlacklistRepository) *AuthMiddleware {
	if tokens == nil {
		return nil
	}
	return &AuthMiddleware{tokens: tokens, blacklist: blacklist}
}

func (a *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
			return
		}
		claims, err := a.tokens.ParseAccessToken(r.Context(), parts[1])
		if err != nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "Invalid access token")
			return
		}

		if a.blacklist != nil && claims.JTI != "" {
			blocked, err := a.blacklist.IsAccessTokenBlacklisted(r.Context(), claims.JTI)
			if err != nil {
				respond.WriteError(w, http.StatusInternalServerError, "server_error", "Token check failed")
				return
			}
			if blocked {
				respond.WriteError(w, http.StatusUnauthorized, "token_revoked", "Token revoked")
				return
			}
		}

		ctx := context.WithValue(r.Context(), accessClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAccessClaims extracts access claims from context.
func GetAccessClaims(ctx context.Context) *services.AccessClaims {
	if ctx == nil {
		return nil
	}
	val := ctx.Value(accessClaimsKey)
	if claims, ok := val.(*services.AccessClaims); ok {
		return claims
	}
	return nil
}
