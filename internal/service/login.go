package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (s *ControllerService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	log := logger.FromContext(ctx)

	username := req.Username
	email := req.Email
	password := req.Password

	if username == "" && email == "" || password == "" {
		log.Warn("not enough data to login", zap.Error(domain.ErrNotEnoughData))
		return nil, domain.ErrNotEnoughData
	}
	if email != "" {
		if !isValidEmail(req.Email) {
			log.Warn("invalid email format", zap.Error(domain.ErrWeakEmail))
			return nil, domain.ErrWeakEmail
		}
	}
	if !isValidPassword(req.Password) {
		log.Warn("invalid password format", zap.Error(domain.ErrWeakPassword))
		return nil, domain.ErrWeakPassword
	}

	user, err := s.Storage.GetUserByUsernameEmail(ctx, username, email)
	if err != nil {
		log.Error("failed to get user by username/email", zap.Error(err))
		return nil, fmt.Errorf("failed to get user by username/email: %w", err)
	}
	if user == nil {
		log.Error("nil user", zap.Error(domain.ErrNilUser))
		return nil, domain.ErrNilUser
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Error("failed to compare hash and password", zap.Error(err))
		return nil, fmt.Errorf("failed to compare hash and password: %w", err)
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(user.ID, username, email)
	if err != nil {
		log.Error("failed to generate access token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	var refreshToken string
	refreshToken, err = s.JWTManager.GenerateRefreshToken()
	if err != nil {
		log.Error("failed to generate refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = s.Session.SaveRefreshToken(ctx, user.ID, refreshToken)
	if err != nil {
		log.Error("failed to save refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &auth.LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}, nil
}
