package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/logger"
	"errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (s *AuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	username := req.Username
	email := req.Email
	password := req.Password

	if username == "" && email == "" || password == "" {
		return nil, ErrNotEnoughData
	}
	if email != "" {
		if !isValidEmail(req.Email) {
			return nil, ErrWeakEmail
		}
	}
	if !isValidPassword(req.Password) {
		return nil, ErrWeakPassword
	}

	user, err := s.Storage.GetUserByUsernameEmail(ctx, username, email)
	if err != nil {
		logger.Log.Error("failed to get user by username/email", zap.Error(err))
		return nil, ErrInvCredentials
	}
	if user == nil {
		return nil, ErrInvCredentials
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, ErrInvCredentials
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(user.ID, username, email)
	if err != nil {
		logger.Log.Error("failed to generate access token", zap.Error(err))
		return nil, errors.New("failed to login user")
	}

	var refreshToken string
	refreshToken, err = s.JWTManager.GenerateRefreshToken()
	if err != nil {
		logger.Log.Error("failed to generate refresh token", zap.Error(err))
		return nil, errors.New("failed to login user")
	}

	err = s.Session.SaveRefreshToken(ctx, user.ID, refreshToken)
	if err != nil {
		logger.Log.Error("failed to save refresh token", zap.Error(err))
		return nil, errors.New("failed to login user")
	}

	return &auth.LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}, nil
}
