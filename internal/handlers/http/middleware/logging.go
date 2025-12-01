package middleware

import (
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

// Logger provides structured request logging with zerolog.
type Logger struct {
	Log zerolog.Logger
}

func (l Logger) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		reqID := chimiddleware.GetReqID(r.Context())
		clientID := r.Header.Get("X-Client-ID")
		ua := r.UserAgent()
		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip = r.Header.Get("X-Forwarded-For")
		}
		if ip == "" {
			ip = r.RemoteAddr
		}

		event := l.Log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.Status()).
			Str("ip", ip).
			Str("user_agent", ua).
			Dur("latency", time.Since(start)).
			Str("client_id", clientID)

		if reqID != "" {
			event = event.Str("request_id", reqID)
		}

		event.Msg("http_request")
	})
}
