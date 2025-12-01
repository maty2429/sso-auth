package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"authserver/internal/config"
)

// CORS enforces strict origins and headers.
type CORS struct {
	cfg config.CORSConfig
}

func NewCORS(cfg config.CORSConfig) CORS {
	return CORS{cfg: cfg}
}

func (c CORS) Handler(next http.Handler) http.Handler {
	allowedMethods := strings.Join(c.cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(c.cfg.AllowedHeaders, ", ")
	maxAge := ""
	if c.cfg.MaxAge > 0 {
		maxAge = strconv.FormatInt(int64(c.cfg.MaxAge.Seconds()), 10)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !c.isAllowedOrigin(origin) {
			if origin != "" {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		if c.cfg.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		if maxAge != "" {
			w.Header().Set("Access-Control-Max-Age", maxAge)
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c CORS) isAllowedOrigin(origin string) bool {
	for _, allowed := range c.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimSpace(allowed), origin) {
			return true
		}
	}
	return false
}
