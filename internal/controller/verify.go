package controller

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"fmt"
	"go.uber.org/zap"
)

func (c *Controller) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("method", "verify"))

	log.Info("request started")

	resp, err := c.service.Verify(ctx, req)
	if err != nil {
		log.Error("verify failed", zap.Error(err))
		return nil, fmt.Errorf("verify failed: %w", err)
	}

	log.Info("request ended")

	return resp, err
}
