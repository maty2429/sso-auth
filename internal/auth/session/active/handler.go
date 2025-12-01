package active

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
		sessions, err := svc.ListActive(r.Context(), claims.UserID)
		if err != nil {
			respond.WriteError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		respond.WriteJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
	}
}
