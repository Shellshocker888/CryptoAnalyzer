package grpc

import (
	"context"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func LoggerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	log := logger.FromContext(ctx)

	log = logger.WithTraceID(ctx, log)

	ctx = logger.WithLogger(ctx, log)

	log.Info("incoming request", zap.String("method", info.FullMethod))

	resp, err := handler(ctx, req)
	if err != nil {
		log.Error("request failed", zap.Error(err))
	} else {
		log.Info("request succeeded")
	}

	return resp, err
}
