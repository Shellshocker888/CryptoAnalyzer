package app

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/controller"
	grpc2 "crypto_analyzer_auth_service/internal/infrastructure/grpc"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"crypto_analyzer_auth_service/internal/infrastructure/postgres"
	redisInit "crypto_analyzer_auth_service/internal/infrastructure/redis"
	"crypto_analyzer_auth_service/internal/service"
	"crypto_analyzer_auth_service/internal/storage"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"log"
	"net"
	"time"
)

func Start(ctx context.Context) error {
	err := logger.InitLogger()
	if err != nil {
		log.Printf("failed to init logger: %v", err)
		return fmt.Errorf("failed to init logger: %w", err)
	}
	defer logger.SyncLogger()

	ctx = logger.WithLogger(ctx, logger.Log)

	configMain, err := config.LoadConfig()
	if err != nil {
		logger.Log.Error("failed to load config", zap.Error(err))
		return fmt.Errorf("failed to load config: %w", err)
	}

	DB, err := postgres.InitPostgres(ctx, configMain.PostgresCfg)
	if err != nil {
		logger.Log.Error("failed to init postgres DB", zap.Error(err))
		return fmt.Errorf("failed to init postgres DB: %w", err)
	}
	defer DB.Close()

	redisClient, err := redisInit.InitRedisClient(ctx, configMain.RedisCfg)
	if err != nil {
		logger.Log.Error("failed to init redis client", zap.Error(err))
		return fmt.Errorf("failed to init redis client: %w", err)
	}
	defer redisClient.Close()

	userStorage := storage.NewUserStorage(DB)
	userSessionManager := storage.NewSessionManager(configMain.RedisCfg, redisClient)
	userJWTManager := storage.NewJWTManager(configMain.JwtCfg)

	controllerService := service.NewService(userStorage, userSessionManager, userJWTManager)
	controllerMain := controller.NewController(controllerService, logger.Log)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(grpc2.LoggerInterceptor),
	)
	pb.RegisterAuthServiceServer(grpcServer, controllerMain)

	var listener50051 net.Listener
	listener50051, err = net.Listen("tcp", ":50051")
	if err != nil {
		logger.Log.Error("failed to init listener for port 50051", zap.Error(err))
		return fmt.Errorf("failed to init listener for port 50051: %w", err)
	}

	grpcErrorCh := make(chan error, 1)

	go func() {
		if err = grpcServer.Serve(listener50051); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Log.Error("grpc server failed", zap.Error(err))
			grpcErrorCh <- err
			return
		}

		grpcErrorCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Log.Info("shutting down gRPC server...")

		if err = listener50051.Close(); err != nil {
			logger.Log.Error("failed to close listener", zap.Error(err))
		}

		stoppedCh := make(chan struct{}, 1)

		ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		go func() {
			grpcServer.GracefulStop()
			close(stoppedCh)
		}()

		select {
		case <-ctxShutdown.Done():
			grpcServer.Stop()
			logger.Log.Info("gRPC server force stopped")
		case <-stoppedCh:
			logger.Log.Info("gRPC server gracefully stopped")
		}

	case err = <-grpcErrorCh:
		if err != nil {
			logger.Log.Error("grpc server error", zap.Error(err))
			return fmt.Errorf("grpc server error: %w", err)
		}

		return nil
	}

	return nil
}
