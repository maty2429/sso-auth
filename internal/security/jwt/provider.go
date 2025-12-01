package jwt

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"authserver/internal/config"
	"authserver/internal/domain/entities"
	"authserver/internal/domain/services"
	gjwt "github.com/golang-jwt/jwt/v5"
)

type Provider struct {
	cfg *config.JWTConfig
}

func NewProvider(cfg *config.JWTConfig) *Provider {
	return &Provider{cfg: cfg}
}

func (p *Provider) GenerateAccessToken(ctx context.Context, user *entities.User, clientID string, roles []string, projects []string) (string, time.Time, error) {
	jti, err := newJTI()
	if err != nil {
		return "", time.Time{}, err
	}
	claims := gjwt.MapClaims{
		"sub":       user.ID,
		"aud":       p.cfg.AllowedAud,
		"iss":       p.cfg.Issuer,
		"exp":       time.Now().Add(p.cfg.AccessTTL()).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       jti,
		"client_id": clientID,
		"email":     user.Email,
		"roles":     roles,
		"projects":  projects,
	}
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(p.cfg.AccessSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt: sign access token: %w", err)
	}
	return signed, time.Now().Add(p.cfg.AccessTTL()), nil
}

func (p *Provider) GenerateRefreshToken(ctx context.Context, session *entities.Session) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := gjwt.MapClaims{
		"sid": session.ID,
		"sub": session.UserID,
		"iss": p.cfg.Issuer,
		"exp": session.ExpiresAt.Add(p.cfg.RefreshTTL()).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
	}
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(p.cfg.RefreshSecret))
}

func (p *Provider) ParseAccessToken(ctx context.Context, token string) (*services.AccessClaims, error) {
	parsed, err := gjwt.Parse(token, func(t *gjwt.Token) (any, error) {
		if t.Method != gjwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return []byte(p.cfg.AccessSecret), nil
	}, gjwt.WithLeeway(p.cfg.ClockSkew), gjwt.WithAudience(p.cfg.AllowedAud...), gjwt.WithIssuer(p.cfg.Issuer))
	if err != nil {
		return nil, fmt.Errorf("jwt: parse access token: %w", err)
	}

	mapClaims, ok := parsed.Claims.(gjwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("jwt: invalid claims")
	}

	userID, _ := mapClaims["sub"].(string)
	clientID, _ := mapClaims["client_id"].(string)
	jti, _ := mapClaims["jti"].(string)
	exp, _ := mapClaims["exp"].(float64)
	rolesAny, _ := mapClaims["roles"].([]interface{})
	projectsAny, _ := mapClaims["projects"].([]interface{})

	roles := make([]string, 0, len(rolesAny))
	for _, r := range rolesAny {
		if v, ok := r.(string); ok {
			roles = append(roles, v)
		}
	}
	projects := make([]string, 0, len(projectsAny))
	for _, p := range projectsAny {
		if v, ok := p.(string); ok {
			projects = append(projects, v)
		}
	}

	return &services.AccessClaims{
		UserID:    userID,
		ClientID:  clientID,
		JTI:       jti,
		Roles:     roles,
		Projects:  projects,
		ExpiresAt: time.Unix(int64(exp), 0),
	}, nil
}

func (p *Provider) ParseRefreshToken(ctx context.Context, token string) (*services.RefreshClaims, error) {
	parsed, err := gjwt.Parse(token, func(t *gjwt.Token) (any, error) {
		if t.Method != gjwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return []byte(p.cfg.RefreshSecret), nil
	}, gjwt.WithLeeway(p.cfg.ClockSkew))
	if err != nil {
		return nil, fmt.Errorf("jwt: parse refresh token: %w", err)
	}

	mapClaims, ok := parsed.Claims.(gjwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("jwt: invalid claims")
	}

	sessionID, _ := mapClaims["sid"].(string)
	userID, _ := mapClaims["sub"].(string)
	jti, _ := mapClaims["jti"].(string)
	exp, _ := mapClaims["exp"].(float64)

	return &services.RefreshClaims{
		SessionID: sessionID,
		UserID:    userID,
		JTI:       jti,
		ExpiresAt: time.Unix(int64(exp), 0),
	}, nil
}

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("jwt: jti: %w", err)
	}
	return fmt.Sprintf("%x", b[:]), nil
}
