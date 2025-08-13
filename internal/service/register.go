package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func (s *ControllerService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	log := logger.FromContext(ctx)

	username := req.Username
	email := req.Email
	password := req.Password

	if username == "" || email == "" || password == "" {
		log.Warn("not enough data to register", zap.Error(domain.ErrNotEnoughData))
		return nil, domain.ErrNotEnoughData
	}

	if !isValidEmail(email) {
		log.Warn("invalid email format", zap.Error(domain.ErrWeakEmail))
		return nil, domain.ErrWeakEmail
	}

	if !isValidPassword(password) {
		log.Warn("invalid password format", zap.Error(domain.ErrWeakPassword))
		return nil, domain.ErrWeakPassword
	}

	exists, err := s.Storage.EmailExists(ctx, email)
	if err != nil {
		log.Error("failed to check email", zap.Error(err))
		return nil, fmt.Errorf("failed to check email: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("email has been already taken")
	}

	/*exists, err = s.Storage.UsernameExists(ctx, req.Username)
	if err != nil {
		logger.Log.Error("failed to check username existence", zap.Error(err))
		return nil, errors_my.New("failed to register user")
	}
	if exists {
		return nil, errors_my.New("the username has been already taken")
	}*/

	var passwordHash []byte
	passwordHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", zap.Error(err))
		return nil, fmt.Errorf("failed to generate password hash: %w", err)
	}

	userID := uuid.New().String()

	user := &domain.User{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
	}

	err = s.Storage.CreateUser(ctx, user)
	if err != nil {
		log.Error("failed to create user", zap.Error(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(userID, username, email)
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

	err = s.Session.SaveRefreshToken(ctx, userID, refreshToken)
	if err != nil {
		log.Error("failed to save refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &auth.RegisterResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}, nil
}
