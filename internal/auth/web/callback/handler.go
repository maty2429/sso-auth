package callback

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"authserver/internal/domain/repositories"
	"authserver/internal/handlers/respond"
)

type request struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

func Handler(repo repositories.OIDCStateRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if repo == nil {
			respond.WriteError(w, http.StatusServiceUnavailable, "oidc_not_configured", "OIDC repository missing")
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid body")
			return
		}

		if req.State == "" || req.Nonce == "" || req.CodeVerifier == "" {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "missing state/nonce/code_verifier")
			return
		}

		stateVal, err := repo.GetState(r.Context(), req.State)
		if err != nil || stateVal == "" {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_state", "state not found or expired")
			return
		}
		var statePayload map[string]string
		_ = json.Unmarshal([]byte(stateVal), &statePayload)

		validNonce, err := repo.ValidateNonce(r.Context(), req.Nonce)
		if err != nil || !validNonce {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_nonce", "nonce not found or expired")
			return
		}
		if spNonce := statePayload["nonce"]; spNonce != "" && spNonce != req.Nonce {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_nonce", "nonce mismatch")
			return
		}
		codeChallenge, err := repo.GetPKCE(r.Context(), req.CodeVerifier)
		if err != nil || codeChallenge == "" {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_pkce", "pkce not found or expired")
			return
		}
		if expected := pkceChallenge(req.CodeVerifier); expected != codeChallenge {
			respond.WriteError(w, http.StatusUnauthorized, "invalid_pkce", "pkce mismatch")
			return
		}

		_ = repo.DeleteState(r.Context(), req.State)
		_ = repo.DeleteNonce(r.Context(), req.Nonce)
		_ = repo.DeletePKCE(r.Context(), req.CodeVerifier)

		code := "code_" + req.State

		respond.WriteJSON(w, http.StatusOK, map[string]string{
			"status":         "ok",
			"code":           code,
			"state":          req.State,
			"nonce":          req.Nonce,
			"code_challenge": codeChallenge,
			"expires_in":     "300",
		})
	}
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
