package controller

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (c *Controller) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("method", "register"))

	log.Info("request started")

	resp, err := c.service.Register(ctx, req)
	if err != nil {
		log.Error("register failed", zap.Error(err))
		return nil, fmt.Errorf("register failed: %w", err)
	}

	log.Info("request ended")

	return resp, nil
}
