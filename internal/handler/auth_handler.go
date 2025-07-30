package handler

import (
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/service"
	"go.uber.org/zap"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	service *service.AuthService
	logger  *zap.Logger
}

func NewAuthHandler(service *service.AuthService, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  logger,
	}
}
