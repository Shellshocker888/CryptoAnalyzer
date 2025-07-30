package handler

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"go.uber.org/zap"
)

func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	resp, err := h.service.Register(ctx, req)
	if err != nil {
		h.logger.Error("register failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}
