package services

import (
	"context"
	"fmt"
	"time"

	"authserver/internal/domain/repositories"
)

type AuditService struct {
	repo repositories.AuditLogRepository
}

func NewAuditService(repo repositories.AuditLogRepository) *AuditService {
	return &AuditService{repo: repo}
}

func (a *AuditService) Record(ctx context.Context, userID string, action string, meta map[string]any) {
	if a.repo == nil {
		return
	}
	metaCopy := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		metaCopy[k] = v
	}
	metaCopy["ts"] = time.Now().UTC().Format(time.RFC3339)
	if err := a.repo.Record(ctx, userID, action, metaCopy); err != nil {
		// auditing must never crash auth flow; just log best-effort
		fmt.Println("audit error:", err)
	}
}
