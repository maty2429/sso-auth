package httpserver

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"authserver/internal/auth/login"
	"authserver/internal/auth/logout"
	"authserver/internal/auth/refresh"
	"authserver/internal/auth/revoke"
	sessionactive "authserver/internal/auth/session/active"
	sessionrevoke "authserver/internal/auth/session/revoke"
	sessionrevokeall "authserver/internal/auth/session/revokeall"
	"authserver/internal/auth/userinfo"
	"authserver/internal/auth/web/authorize"
	"authserver/internal/auth/web/callback"
	webtoken "authserver/internal/auth/web/token"
	"authserver/internal/config"
	"authserver/internal/domain/repositories"
	"authserver/internal/domain/services"
	hmiddleware "authserver/internal/handlers/http/middleware"
	"authserver/internal/security/ratelimit"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

// Server wires the HTTP router and dependencies.
type Server struct {
	router *chi.Mux
	cfg    *config.Config
	logger zerolog.Logger
	server *http.Server
}

type Dependencies struct {
	AuthService *services.AuthService
	Limiter     ratelimit.Middleware
	Tokens      services.TokenManager
	Blacklist   repositories.TokenBlacklistRepository
	OIDCRepo    repositories.OIDCStateRepository
	ClientRepo  repositories.AuthClientRepository
	OIDCConfig  *config.OIDCConfig
	SessionSvc  *services.SessionService
}

func NewServer(cfg *config.Config, logger zerolog.Logger, deps Dependencies) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(hmiddleware.NewCORS(cfg.CORS).Handler)
	r.Use(hmiddleware.Logger{Log: logger}.Handler)

	if deps.Limiter != nil {
		r.Use(deps.Limiter.HTTP)
	}

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	authMW := hmiddleware.NewAuthMiddleware(deps.Tokens, deps.Blacklist)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", login.Handler(deps.AuthService))
		r.Post("/refresh", refresh.Handler(deps.AuthService))
		r.Post("/web/authorize", authorize.Handler(deps.OIDCRepo, deps.ClientRepo, deps.OIDCConfig))
		r.Post("/web/callback", callback.Handler(deps.OIDCRepo))
		r.Post("/web/token", webtoken.Handler())
		r.Group(func(r chi.Router) {
			if authMW != nil {
				r.Use(authMW.Handler)
			}
			r.Post("/logout", logout.Handler(deps.AuthService))
			r.Get("/userinfo", userinfo.Handler())
			r.Post("/revoke", revoke.Handler(deps.AuthService))
			r.Post("/session/revoke", sessionrevoke.Handler(deps.SessionSvc))
			r.Post("/session/revoke-all", sessionrevokeall.Handler(deps.SessionSvc))
			r.Get("/session/active", sessionactive.Handler(deps.SessionSvc))
		})
	})

	s := &http.Server{
		Addr:         cfgServerAddr(cfg),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	return &Server{
		router: r,
		cfg:    cfg,
		logger: logger,
		server: s,
	}
}

func (s *Server) Start() error {
	s.logger.Info().Str("addr", s.server.Addr).Msg("starting http server")
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func cfgServerAddr(cfg *config.Config) string {
	return cfg.Server.Host + ":" + strconv.Itoa(cfg.Server.Port)
}
