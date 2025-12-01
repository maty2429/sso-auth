package repositories

import "context"

// Redis-backed rate limiting.
type RateLimitRepository interface {
	IncrementUserAttempts(ctx context.Context, userID string) (int, error)
	IncrementIPAttempts(ctx context.Context, ip string) (int, error)
	IncrementRUTAttempts(ctx context.Context, rut string) (int, error)
	IncrementDeviceAttempts(ctx context.Context, deviceID string) (int, error)

	ResetUserAttempts(ctx context.Context, userID string) error
	ResetIPAttempts(ctx context.Context, ip string) error
	ResetRUTAttempts(ctx context.Context, rut string) error
	ResetDeviceAttempts(ctx context.Context, deviceID string) error
}

// Blacklist for tokens and sessions.
type TokenBlacklistRepository interface {
	BlacklistAccessToken(ctx context.Context, jti string, ttlSeconds int64) error
	BlacklistRefreshToken(ctx context.Context, jti string, ttlSeconds int64) error
	BlacklistSession(ctx context.Context, sessionID string, ttlSeconds int64) error
	BlacklistUser(ctx context.Context, userID string, ttlSeconds int64) error

	IsAccessTokenBlacklisted(ctx context.Context, jti string) (bool, error)
	IsRefreshTokenBlacklisted(ctx context.Context, jti string) (bool, error)
	IsSessionBlacklisted(ctx context.Context, sessionID string) (bool, error)
	IsUserBlacklisted(ctx context.Context, userID string) (bool, error)
}

// OIDC state/nonce/PKCE temporary storage.
type OIDCStateRepository interface {
	SaveState(ctx context.Context, state string, data string, ttlSeconds int64) error
	GetState(ctx context.Context, state string) (string, error)
	DeleteState(ctx context.Context, state string) error

	SaveNonce(ctx context.Context, nonce string, ttlSeconds int64) error
	ValidateNonce(ctx context.Context, nonce string) (bool, error)
	DeleteNonce(ctx context.Context, nonce string) error

	SavePKCE(ctx context.Context, codeVerifier string, codeChallenge string, ttlSeconds int64) error
	GetPKCE(ctx context.Context, codeVerifier string) (string, error)
	DeletePKCE(ctx context.Context, codeVerifier string) error
}

// Device security for mobile flows.
type DeviceSecurityRepository interface {
	IncrementAttempts(ctx context.Context, deviceID string) (int, error)
	ResetAttempts(ctx context.Context, deviceID string) error
	IsBlocked(ctx context.Context, deviceID string) (bool, error)
	BlockDevice(ctx context.Context, deviceID string, ttlSeconds int64) error
	SaveFingerprint(ctx context.Context, deviceID string, payload string, ttlSeconds int64) error
	GetFingerprint(ctx context.Context, deviceID string) (string, error)
}

// Temporary user locks.
type UserTempLockRepository interface {
	LockUser(ctx context.Context, userID string, ttlSeconds int64) error
	IsUserLocked(ctx context.Context, userID string) (bool, error)
	UnlockUser(ctx context.Context, userID string) error
}

// Optional recovery repository for password/email flows.
type RecoveryRepository interface {
	SavePasswordResetToken(ctx context.Context, token string, userID string, ttlSeconds int64) error
	GetUserIDByPasswordResetToken(ctx context.Context, token string) (string, error)
	DeletePasswordResetToken(ctx context.Context, token string) error

	SaveEmailVerification(ctx context.Context, token string, userID string, ttlSeconds int64) error
	GetEmailVerification(ctx context.Context, token string) (string, error)
	DeleteEmailVerification(ctx context.Context, token string) error
}
