package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"authserver/internal/domain/services"
	"authserver/internal/handlers/respond"

	"github.com/go-playground/validator/v10"
)

type request struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	ClientID string `json:"client_id" validate:"required"`
	DeviceID string `json:"device_id"`
}

type response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
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

		ip := r.RemoteAddr
		userAgent := r.UserAgent()

		tokens, err := auth.Login(r.Context(), req.Email, req.Password, req.ClientID, ip, userAgent, req.DeviceID)
		if err != nil {
			status, code, msg := mapLoginError(err)
			respond.WriteError(w, status, code, msg)
			return
		}

		respond.WriteJSON(w, http.StatusOK, response{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt.Unix(),
		})
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func mapLoginError(err error) (int, string, string) {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials", "Usuario o contraseña incorrectos"
	case errors.Is(err, services.ErrInactiveUser):
		return http.StatusUnauthorized, "inactive_user", "Usuario inactivo"
	case strings.Contains(err.Error(), "too many requests"):
		return http.StatusTooManyRequests, "rate_limited", "Demasiados intentos, intente más tarde"
	default:
		return http.StatusInternalServerError, "server_error", "Error interno"
	}
}
