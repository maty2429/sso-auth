package refresh

import (
	"encoding/json"
	"net/http"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/respond"
	"github.com/go-playground/validator/v10"
)

type request struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	ClientID     string `json:"client_id" validate:"required"`
}

var validate = validator.New()

func Handler(auth *services.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid body")
			return
		}
		if err := validate.Struct(req); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		tokens, err := auth.Refresh(r.Context(), req.RefreshToken, req.ClientID)
		if err != nil {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		respond.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"expires_at":    tokens.ExpiresAt.Unix(),
		})
	}
}
