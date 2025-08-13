package controller

import (
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/service"
	"go.uber.org/zap"
)

type Controller struct {
	pb.UnimplementedAuthServiceServer
	service *service.ControllerService
}

func NewController(service *service.ControllerService, logger *zap.Logger) *Controller {
	return &Controller{
		service: service,
	}
}
