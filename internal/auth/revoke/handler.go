package revoke

import (
	"encoding/json"
	"net/http"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/http/middleware"
	"authserver/internal/handlers/respond"
)

type request struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	AccessJTI string `json:"access_jti"`
	TTL       int64  `json:"ttl_seconds"`
}

func Handler(auth *services.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.GetAccessClaims(r.Context())
		if claims == nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", "No claims")
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid body")
			return
		}

		// Default TTL to remaining access token lifetime if not provided.
		ttl := req.TTL

	targetUser := req.UserID
	if targetUser == "" {
		targetUser = claims.UserID
	}
	if targetUser != claims.UserID {
		respond.WriteError(w, http.StatusForbidden, "forbidden", "cannot revoke other users")
		return
	}

	if err := auth.RevokeAccess(r.Context(), targetUser, req.SessionID, req.AccessJTI, ttl); err != nil {
		respond.WriteError(w, http.StatusBadRequest, "revoke_failed", err.Error())
		return
	}

		respond.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
