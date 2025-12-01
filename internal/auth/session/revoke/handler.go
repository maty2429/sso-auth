package revoke

import (
	"encoding/json"
	"net/http"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/http/middleware"
	"authserver/internal/handlers/respond"
)

type request struct {
	SessionID string `json:"session_id" validate:"required"`
}

func Handler(svc *services.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetAccessClaims(r.Context())
		if claims == nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "No claims")
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid body")
			return
		}
		if err := svc.Revoke(r.Context(), req.SessionID); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "revoke_failed", err.Error())
			return
		}
		respond.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
