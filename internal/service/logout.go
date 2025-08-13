package service

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (s *ControllerService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	log := logger.FromContext(ctx)

	refreshToken := req.GetRefreshToken()
	if refreshToken == "" {
		log.Warn("empty refresh token", zap.Error(domain.ErrNoRefreshToken))
		return nil, domain.ErrNoRefreshToken
	}

	err := s.Session.DeleteRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Error("failed to delete refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return &pb.LogoutResponse{}, nil
}
