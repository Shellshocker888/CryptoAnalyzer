package handler

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"go.uber.org/zap"
)

func (h *AuthHandler) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	resp, err := h.service.Refresh(ctx, req)
	if err != nil {
		h.logger.Error("failed to refresh", zap.Error(err))
		return nil, err
	}

	return resp, err
}
