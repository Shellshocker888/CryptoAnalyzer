package handler

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"go.uber.org/zap"
)

func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	resp, err := h.service.Login(ctx, req)
	if err != nil {
		h.logger.Error("login failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}
