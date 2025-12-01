package userinfo

import (
	"net/http"

	"authserver/internal/handlers/http/middleware"
	"authserver/internal/handlers/respond"
)

func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetAccessClaims(r.Context())
		if claims == nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "No claims")
			return
		}
		respond.WriteJSON(w, http.StatusOK, map[string]any{
			"user_id":   claims.UserID,
			"client_id": claims.ClientID,
			"exp":       claims.ExpiresAt.Unix(),
		})
	}
}
