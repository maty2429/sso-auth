package service

import (
	"context"
	"errors"
	"time"

	"sso/internal/core/domain"
	"sso/internal/core/ports"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo  ports.UserRepository
	tokenRepo ports.TokenRepository
	jwtSecret []byte
}

func NewAuthService(userRepo ports.UserRepository, tokenRepo ports.TokenRepository, jwtSecret string) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, string, error) {
	// 1. Buscar usuario
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", errors.New("invalid credentials")
	}

	// 2. Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", errors.New("invalid credentials")
	}

	// 3. Generar Access Token (JWT)
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	// 4. Generar Refresh Token (Opaco)
	refreshTokenStr := uuid.New().String()
	refreshTokenHash, _ := bcrypt.GenerateFromPassword([]byte(refreshTokenStr), bcrypt.DefaultCost)

	refreshToken := &domain.RefreshToken{
		UserID:    user.ID,
		TokenHash: string(refreshTokenHash),
		ExpiresAt: time.Now().Add(24 * 7 * time.Hour), // 7 días
	}

	// 5. Guardar Refresh Token
	if err := s.tokenRepo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return "", "", err
	}

	return accessToken, refreshTokenStr, nil
}

func (s *AuthService) Register(ctx context.Context, user *domain.User, password string) (*domain.User, error) {
	// 1. Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = string(hashedPassword)

	// 2. Guardar usuario
	return s.userRepo.Save(ctx, user)
}

func (s *AuthService) ValidateToken(tokenString string) (*domain.User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("invalid subject")
	}

	// Aquí podrías buscar el usuario en la BD si necesitas más datos o verificar si sigue activo
	// Por ahora devolvemos un usuario parcial con el ID
	uid, _ := uuid.Parse(userIDStr)
	return &domain.User{ID: uid}, nil
}

func (s *AuthService) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
