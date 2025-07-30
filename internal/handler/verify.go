package handler

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"go.uber.org/zap"
)

func (h *AuthHandler) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	resp, err := h.service.Verify(ctx, req)
	if err != nil {
		h.logger.Error("failed to verify", zap.Error(err))
		return nil, err
	}

	return resp, err
}
