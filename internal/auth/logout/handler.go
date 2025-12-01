package logout

import (
	"encoding/json"
	"net/http"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/respond"
	"github.com/go-playground/validator/v10"
)

type request struct {
	SessionID    string `json:"session_id" validate:"required"`
	RefreshToken string `json:"refresh_token"`
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

		if err := auth.Logout(r.Context(), req.SessionID, req.RefreshToken); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "logout_failed", err.Error())
			return
		}

		respond.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
