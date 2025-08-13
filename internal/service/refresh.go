package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (s *ControllerService) Refresh(ctx context.Context, req *auth.RefreshRequest) (*auth.RefreshResponse, error) {
	log := logger.FromContext(ctx)

	refreshToken := req.GetRefreshToken()
	if refreshToken == "" {
		log.Warn("empty refresh token", zap.Error(domain.ErrNoRefreshToken))
		return nil, domain.ErrNoRefreshToken
	}

	userID, err := s.Session.GetUserIDByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Error("failed to get userID by refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to get userID by refresh token: %w", err)
	}

	err = s.Session.DeleteRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Error("failed to delete refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to delete refresh token: %w", err)
	}

	var user *domain.User
	user, err = s.Storage.GetUserByUserID(ctx, userID)
	if err != nil {
		log.Error("failed to get user by userID", zap.Error(err))
		return nil, fmt.Errorf("failed to get user by userID: %w", err)
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(userID, user.Username, user.Email)
	if err != nil {
		log.Error("failed to generate access token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	var newRefreshToken string
	newRefreshToken, err = s.JWTManager.GenerateRefreshToken()
	if err != nil {
		log.Error("failed to generate refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = s.Session.SaveRefreshToken(ctx, userID, newRefreshToken)
	if err != nil {
		log.Error("failed to save refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &auth.RefreshResponse{
		Token:        accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
