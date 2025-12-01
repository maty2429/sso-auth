package revokeall

import (
	"net/http"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/http/middleware"
	"authserver/internal/handlers/respond"
)

func Handler(svc *services.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetAccessClaims(r.Context())
		if claims == nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "No claims")
			return
		}
		if err := svc.RevokeAll(r.Context(), claims.UserID); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "revoke_failed", err.Error())
			return
		}
		respond.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked_all"})
	}
}
