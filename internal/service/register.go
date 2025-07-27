package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func (s *AuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	exists, err := s.Storage.EmailExists(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}

	if exists {
		return nil, errors.New("the email has been already taken")
	}

	exists, err = s.Storage.UsernameExists(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}

	if exists {
		return nil, errors.New("the username has been already taken")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hash for password: %w", err)
	}

	userID := uuid.New().String()

	user := &domain.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
	}

	err = s.Storage.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	accessToken, err := s.JWTManager.GenerateAccessToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate accessToken: %w", err)
	}

	refreshToken, err := s.JWTManager.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate accessToken: %w", err)
	}

	err = s.Session.SaveRefreshToken(ctx, userID, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to save session with refresh token: %w", err)
	}

	return &auth.RegisterResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}, nil
}
