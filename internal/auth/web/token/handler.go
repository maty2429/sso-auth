package token

import (
	"net/http"

	"authserver/internal/handlers/respond"
)

// Placeholder token exchange; real implementation should validate code, PKCE, and issue tokens.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respond.WriteError(w, http.StatusNotImplemented, "not_implemented", "OIDC token exchange not implemented")
	}
}
