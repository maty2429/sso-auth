package ratelimit

import (
	"context"
	"fmt"
)

// LoginLimiter wraps the existing rate limiter to enforce per-IP/user/device keys.
type LoginLimiter struct {
	lim RateLimiter
}

type RateLimiter interface {
	Allow(ctx context.Context, key string) error
}

func NewLoginLimiter(lim RateLimiter) *LoginLimiter {
	return &LoginLimiter{lim: lim}
}

func (l *LoginLimiter) AllowAll(ctx context.Context, email, ip, device string) error {
	if l.lim == nil {
		return nil
	}
	keys := []string{}
	if email != "" {
		keys = append(keys, fmt.Sprintf("email:%s", email))
	}
	if ip != "" {
		keys = append(keys, fmt.Sprintf("ip:%s", ip))
	}
	if device != "" {
		keys = append(keys, fmt.Sprintf("device:%s", device))
	}
	for _, k := range keys {
		if err := l.lim.Allow(ctx, k); err != nil {
			return err
		}
	}
	return nil
}
