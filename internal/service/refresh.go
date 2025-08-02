package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/logger"
	"errors"
	"go.uber.org/zap"
)

func (s *AuthService) Refresh(ctx context.Context, req *auth.RefreshRequest) (*auth.RefreshResponse, error) {
	userID, err := s.Session.GetUserIDByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		logger.Log.Error("failed to get userID by refresh token", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	err = s.Session.DeleteRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		logger.Log.Error("failed to delete old refresh token", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	var user *domain.User
	user, err = s.Storage.GetUserByUserID(ctx, userID)
	if err != nil {
		logger.Log.Error("failed to get user data by userID", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(userID, user.Username, user.Email)
	if err != nil {
		logger.Log.Error("failed to generate access token", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	var newRefreshToken string
	newRefreshToken, err = s.JWTManager.GenerateRefreshToken()
	if err != nil {
		logger.Log.Error("failed to generate new refresh token", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	err = s.Session.SaveRefreshToken(ctx, userID, newRefreshToken)
	if err != nil {
		logger.Log.Error("failed to save new refresh token", zap.Error(err))
		return nil, errors.New("failed to refresh token")
	}

	return &auth.RefreshResponse{
		Token:        accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
