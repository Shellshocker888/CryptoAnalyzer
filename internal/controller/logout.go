package controller

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (c *Controller) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("method", "logout"))

	log.Info("request started")

	resp, err := c.service.Logout(ctx, req)
	if err != nil {
		log.Error("logout failed", zap.Error(err))
		return nil, fmt.Errorf("logout failed: %w", err)
	}

	log.Info("request ended")

	return resp, nil
}
