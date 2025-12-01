package authorize

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authserver/internal/config"
	"authserver/internal/domain/repositories"
	"authserver/internal/handlers/respond"
)

type request struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func Handler(repo repositories.OIDCStateRepository, clientRepo repositories.AuthClientRepository, cfg *config.OIDCConfig) http.HandlerFunc {
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

		if req.ClientID == "" || req.RedirectURI == "" {
			respond.WriteError(w, http.StatusBadRequest, "invalid_request", "client_id and redirect_uri required")
			return
		}
		if cfg != nil && len(cfg.AllowedRedirects) > 0 && !isAllowedRedirect(req.RedirectURI, cfg.AllowedRedirects) {
			respond.WriteError(w, http.StatusBadRequest, "invalid_redirect", "redirect_uri not allowed")
			return
		}
		if clientRepo != nil {
			client, err := clientRepo.GetByClientID(r.Context(), req.ClientID)
			if err != nil || client == nil || !client.IsActive {
				respond.WriteError(w, http.StatusUnauthorized, "invalid_client", "client not found or inactive")
				return
			}
			if len(client.RedirectURIs) > 0 && !isAllowedRedirect(req.RedirectURI, client.RedirectURIs) {
				respond.WriteError(w, http.StatusBadRequest, "invalid_redirect", "redirect_uri not registered")
				return
			}
		}

		// Generate state, nonce, code_verifier/challenge
		state := randomString(16)
		nonce := randomString(16)
		codeVerifier := randomString(32)
		challenge := pkceChallenge(codeVerifier)

		// Persist with TTL 5 minutes
		ttl := int64((5 * time.Minute).Seconds())
		codePayload, _ := json.Marshal(map[string]string{
			"client_id":      req.ClientID,
			"redirect_uri":   req.RedirectURI,
			"code_challenge": challenge,
			"nonce":          nonce,
		})
		if err := repo.SaveState(r.Context(), state, string(codePayload), ttl); err != nil {
			respond.WriteError(w, http.StatusInternalServerError, "oidc_state_error", err.Error())
			return
		}
		if err := repo.SaveNonce(r.Context(), nonce, ttl); err != nil {
			respond.WriteError(w, http.StatusInternalServerError, "oidc_nonce_error", err.Error())
			return
		}
		if err := repo.SavePKCE(r.Context(), codeVerifier, challenge, ttl); err != nil {
			respond.WriteError(w, http.StatusInternalServerError, "oidc_pkce_error", err.Error())
			return
		}

		respond.WriteJSON(w, http.StatusOK, map[string]string{
			"state":            state,
			"nonce":            nonce,
			"code_verifier":    codeVerifier,
			"code_challenge":   challenge,
			"challenge_method": "S256",
		})
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func isAllowedRedirect(target string, allowed []string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	for _, a := range allowed {
		au, err := url.Parse(a)
		if err != nil {
			continue
		}
		if strings.EqualFold(u.Scheme, au.Scheme) && strings.EqualFold(u.Host, au.Host) {
			return true
		}
	}
	return false
}
