package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
	"github.com/rs/zerolog"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInactiveUser       = errors.New("user is inactive")
	ErrUserLocked         = errors.New("user locked temporarily")
	ErrDeviceBlocked      = errors.New("device blocked")
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) error
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type TokenManager interface {
	GenerateAccessToken(ctx context.Context, user *entities.User, clientID string, roles []string, projects []string) (string, time.Time, error)
	GenerateRefreshToken(ctx context.Context, session *entities.Session) (string, error)
	ParseAccessToken(ctx context.Context, token string) (*AccessClaims, error)
	ParseRefreshToken(ctx context.Context, token string) (*RefreshClaims, error)
}

type RefreshClaims struct {
	SessionID string
	UserID    string
	JTI       string
	ExpiresAt time.Time
}

type AccessClaims struct {
	UserID    string
	ClientID  string
	JTI       string
	Roles     []string
	Projects  []string
	ExpiresAt time.Time
}

type RateLimiter interface {
	Allow(ctx context.Context, key string) error
}

type UserTempLock interface {
	IsUserLocked(ctx context.Context, userID string) (bool, error)
	LockUser(ctx context.Context, userID string, ttlSeconds int64) error
}

type DeviceSecurity interface {
	IsBlocked(ctx context.Context, deviceID string) (bool, error)
	IncrementAttempts(ctx context.Context, deviceID string) (int, error)
	BlockDevice(ctx context.Context, deviceID string, ttlSeconds int64) error
}

type AuthService struct {
	users         repositories.UserRepository
	sessions      repositories.SessionRepository
	refreshRepo   repositories.RefreshTokenRepository
	blacklistRepo repositories.TokenBlacklistRepository
	roleRepo      repositories.RoleRepository
	projectRepo   repositories.ProjectRepository
	audit         *AuditService
	userLock      UserTempLock
	deviceSec     DeviceSecurity
	securityCfg   SecuritySettings
	hasher        PasswordHasher
	tokens        TokenManager
	limiter       RateLimiter
	logger        zerolog.Logger
	now           func() time.Time
}

type SecuritySettings struct {
	MaxDeviceAttempts  int
	DeviceBlockSeconds int64
	UserLockSeconds    int64
}

func NewAuthService(
	users repositories.UserRepository,
	sessions repositories.SessionRepository,
	refreshRepo repositories.RefreshTokenRepository,
	blacklistRepo repositories.TokenBlacklistRepository,
	roleRepo repositories.RoleRepository,
	projectRepo repositories.ProjectRepository,
	userLock UserTempLock,
	deviceSec DeviceSecurity,
	audit *AuditService,
	securityCfg SecuritySettings,
	hasher PasswordHasher,
	tokens TokenManager,
	limiter RateLimiter,
	logger zerolog.Logger,
) *AuthService {
	return &AuthService{
		users:         users,
		sessions:      sessions,
		refreshRepo:   refreshRepo,
		blacklistRepo: blacklistRepo,
		roleRepo:      roleRepo,
		projectRepo:   projectRepo,
		audit:         audit,
		userLock:      userLock,
		deviceSec:     deviceSec,
		securityCfg:   securityCfg,
		hasher:        hasher,
		tokens:        tokens,
		limiter:       limiter,
		logger:        logger,
		now:           time.Now,
	}
}

func (s *AuthService) Login(ctx context.Context, email, password, clientID, ip, userAgent, deviceID string) (TokenPair, error) {
	if s.limiter != nil {
		if err := s.limiter.Allow(ctx, email); err != nil {
			return TokenPair{}, err
		}
		if ip != "" {
			if err := s.limiter.Allow(ctx, "ip:"+ip); err != nil {
				return TokenPair{}, err
			}
		}
		if clientID != "" {
			if err := s.limiter.Allow(ctx, "client:"+clientID); err != nil {
				return TokenPair{}, err
			}
		}
		if deviceID != "" {
			if err := s.limiter.Allow(ctx, "device:"+deviceID); err != nil {
				return TokenPair{}, err
			}
		}
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return TokenPair{}, fmt.Errorf("login: get user: %w", err)
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, ErrInactiveUser
	}
	if s.userLock != nil {
		if locked, err := s.userLock.IsUserLocked(ctx, user.ID); err == nil && locked {
			return TokenPair{}, ErrUserLocked
		}
	}
	if s.deviceSec != nil && deviceID != "" {
		if blocked, err := s.deviceSec.IsBlocked(ctx, deviceID); err == nil && blocked {
			return TokenPair{}, ErrDeviceBlocked
		}
	}
	if s.audit != nil {
		s.audit.Record(ctx, user.ID, "login_attempt", map[string]any{"ip": ip, "client_id": clientID, "device_id": deviceID})
	}

	if err := s.hasher.Verify(password, user.PasswordHash); err != nil {
		s.handleFailedAttempt(ctx, user.ID, deviceID)
		if s.audit != nil {
			s.audit.Record(ctx, user.ID, "login_failed", map[string]any{"reason": "invalid_credentials"})
		}
		return TokenPair{}, ErrInvalidCredentials
	}

	session := &entities.Session{
		ID:        fmt.Sprintf("sess_%d", s.now().UnixNano()),
		UserID:    user.ID,
		ClientID:  clientID,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: s.now(),
		ExpiresAt: s.now().Add(30 * 24 * time.Hour),
		Revoked:   false,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return TokenPair{}, fmt.Errorf("login: create session: %w", err)
	}

	roles, projects := s.fetchRolesProjects(ctx, user.ID)

	access, exp, err := s.tokens.GenerateAccessToken(ctx, user, clientID, roles, projects)
	if err != nil {
		return TokenPair{}, fmt.Errorf("login: access token: %w", err)
	}
	refresh, err := s.tokens.GenerateRefreshToken(ctx, session)
	if err != nil {
		return TokenPair{}, fmt.Errorf("login: refresh token: %w", err)
	}
	if err := s.refreshRepo.Save(ctx, refresh, session.ID, session.ExpiresAt.Unix()); err != nil {
		return TokenPair{}, fmt.Errorf("login: persist refresh token: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, user.ID, "login_success", map[string]any{"session_id": session.ID, "client_id": clientID})
	}

	return TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    exp,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, token string, clientID string) (TokenPair, error) {
	claims, err := s.tokens.ParseRefreshToken(ctx, token)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: parse token: %w", err)
	}

	if s.blacklistRepo != nil {
		if blocked, err := s.blacklistRepo.IsRefreshTokenBlacklisted(ctx, claims.JTI); err == nil && blocked {
			return TokenPair{}, fmt.Errorf("refresh: token revoked")
		} else if err != nil {
			return TokenPair{}, fmt.Errorf("refresh: blacklist check: %w", err)
		}
	}

	session, err := s.sessions.GetByID(ctx, claims.SessionID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: get session: %w", err)
	}
	if session == nil || session.Revoked || session.ExpiresAt.Before(s.now()) {
		return TokenPair{}, fmt.Errorf("refresh: session invalid")
	}

	user, err := s.users.GetByID(ctx, claims.UserID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: get user: %w", err)
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, ErrInactiveUser
	}

	roles, projects := s.fetchRolesProjects(ctx, user.ID)

	access, exp, err := s.tokens.GenerateAccessToken(ctx, user, clientID, roles, projects)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: access token: %w", err)
	}
	newRefresh, err := s.tokens.GenerateRefreshToken(ctx, session)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: refresh token: %w", err)
	}
	if err := s.refreshRepo.Save(ctx, newRefresh, session.ID, session.ExpiresAt.Unix()); err != nil {
		return TokenPair{}, fmt.Errorf("refresh: persist refresh token: %w", err)
	}
	if err := s.refreshRepo.Delete(ctx, token); err != nil {
		s.logger.Warn().Err(err).Msg("refresh: old refresh token deletion failed")
	}
	if s.blacklistRepo != nil {
		ttl := int64(claims.ExpiresAt.Sub(s.now()).Seconds())
		if ttl < 0 {
			ttl = 0
		}
		if err := s.blacklistRepo.BlacklistRefreshToken(ctx, claims.JTI, ttl); err != nil {
			s.logger.Warn().Err(err).Msg("refresh: blacklist old refresh token failed")
		}
	}
	if s.audit != nil {
		s.audit.Record(ctx, user.ID, "refresh_success", map[string]any{"session_id": session.ID, "client_id": clientID})
	}

	return TokenPair{
		AccessToken:  access,
		RefreshToken: newRefresh,
		ExpiresAt:    exp,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string, refreshToken string) error {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return fmt.Errorf("logout: revoke session: %w", err)
	}
	if refreshToken != "" {
		if err := s.refreshRepo.Delete(ctx, refreshToken); err != nil {
			s.logger.Warn().Err(err).Str("session_id", sessionID).Msg("logout: refresh token removal failed")
		}
	}
	if s.blacklistRepo != nil {
		_ = s.blacklistRepo.BlacklistSession(ctx, sessionID, 0)
		if refreshToken != "" {
			if claims, err := s.tokens.ParseRefreshToken(ctx, refreshToken); err == nil {
				ttl := int64(claims.ExpiresAt.Sub(s.now()).Seconds())
				if ttl < 0 {
					ttl = 0
				}
				_ = s.blacklistRepo.BlacklistRefreshToken(ctx, claims.JTI, ttl)
			}
		}
	}
	if s.audit != nil {
		s.audit.Record(ctx, "", "logout", map[string]any{"session_id": sessionID})
	}
	return nil
}

func (s *AuthService) RevokeAccess(ctx context.Context, userID, sessionID string, accessJTI string, ttlSeconds int64) error {
	if s.blacklistRepo == nil {
		return errors.New("blacklist not configured")
	}
	if accessJTI != "" {
		if err := s.blacklistRepo.BlacklistAccessToken(ctx, accessJTI, ttlSeconds); err != nil {
			return err
		}
	}
	if sessionID != "" {
		if err := s.blacklistRepo.BlacklistSession(ctx, sessionID, ttlSeconds); err != nil {
			return err
		}
	}
	if userID != "" {
		if err := s.blacklistRepo.BlacklistUser(ctx, userID, ttlSeconds); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuthService) handleFailedAttempt(ctx context.Context, userID, deviceID string) {
	if s.deviceSec != nil && deviceID != "" {
		if attempts, err := s.deviceSec.IncrementAttempts(ctx, deviceID); err == nil {
			if attempts >= s.securityCfg.MaxDeviceAttempts {
				_ = s.deviceSec.BlockDevice(ctx, deviceID, s.securityCfg.DeviceBlockSeconds)
			}
		}
	}
	if s.userLock != nil && userID != "" {
		if s.securityCfg.UserLockSeconds > 0 {
			_ = s.userLock.LockUser(ctx, userID, s.securityCfg.UserLockSeconds)
		}
	}
}

func (s *AuthService) fetchRolesProjects(ctx context.Context, userID string) ([]string, []string) {
	roles := []string{}
	projects := []string{}
	if s.roleRepo != nil {
		if rs, err := s.roleRepo.GetRolesByUser(ctx, userID); err == nil {
			for _, r := range rs {
				roles = append(roles, r.Name)
			}
		}
	}
	if s.projectRepo != nil {
		if ps, err := s.projectRepo.GetProjectsByUser(ctx, userID); err == nil {
			for _, p := range ps {
				projects = append(projects, p.Name)
			}
		}
	}
	return roles, projects
}
