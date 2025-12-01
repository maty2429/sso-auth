package services

import (
	"context"
	"fmt"
	"time"

	"authserver/internal/domain/entities"
	"authserver/internal/domain/repositories"
)

type SessionService struct {
	sessions  repositories.SessionRepository
	refreshes repositories.RefreshTokenRepository
	blacklist repositories.TokenBlacklistRepository
	audit     *AuditService
	now       func() time.Time
}

func NewSessionService(sessions repositories.SessionRepository, refreshes repositories.RefreshTokenRepository, blacklist repositories.TokenBlacklistRepository, audit *AuditService) *SessionService {
	return &SessionService{
		sessions:  sessions,
		refreshes: refreshes,
		blacklist: blacklist,
		audit:     audit,
		now:       time.Now,
	}
}

func (s *SessionService) Revoke(ctx context.Context, sessionID string) error {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	if s.blacklist != nil {
		_ = s.blacklist.BlacklistSession(ctx, sessionID, 0)
	}
	if s.audit != nil {
		s.audit.Record(ctx, "", "session_revoke", map[string]any{"session_id": sessionID})
	}
	return nil
}

func (s *SessionService) RevokeAll(ctx context.Context, userID string) error {
	if s.blacklist != nil {
		_ = s.blacklist.BlacklistUser(ctx, userID, 0)
	}
	if s.refreshes != nil {
		_ = s.refreshes.DeleteByUser(ctx, userID)
	}
	if s.audit != nil {
		s.audit.Record(ctx, userID, "session_revoke_all", nil)
	}
	return nil
}

func (s *SessionService) ListActive(ctx context.Context, userID string) ([]*entities.Session, error) {
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}
	sess, err := s.sessions.ListActiveByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*entities.Session, 0, len(sess))
	for i := range sess {
		result = append(result, &sess[i])
	}
	return result, nil
}
