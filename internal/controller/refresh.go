package controller

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (c *Controller) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("method", "refresh"))

	log.Info("request started")

	resp, err := c.service.Refresh(ctx, req)
	if err != nil {
		log.Error("refresh failed", zap.Error(err))
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	log.Info("request ended")

	return resp, nil
}
