package tests

import (
	"context"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/config/model"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"crypto_analyzer_auth_service/internal/infrastructure/postgres"
	redisInit "crypto_analyzer_auth_service/internal/infrastructure/redis"
	"crypto_analyzer_auth_service/internal/service"
	"crypto_analyzer_auth_service/internal/storage"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"os"
	"testing"
	"time"
)

var (
	DB                 *sql.DB
	redisClient        *redis.Client
	userStorage        *storage.UserPostgresStorage
	userSessionManager *storage.SessionManager
	userJWTManager     *storage.JWTManager
	controllerService  *service.ControllerService
)

func TestMain(m *testing.M) {
	err := logger.InitTestLogger()
	if err != nil {
		zap.L().Fatal("failed to init test logger", zap.Error(err))
	}
	defer logger.SyncLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = os.Setenv("APP_ENV", "test")
	if err != nil {
		zap.L().Fatal("failed to set test environment variable", zap.Error(err))
	}

	var configMain *model.Config
	if configMain, err = config.LoadConfig(); err != nil {
		zap.L().Fatal("failed to load config", zap.Error(err))
	}

	DB, err = postgres.InitPostgres(ctx, configMain.PostgresCfg)
	if err != nil {
		zap.L().Fatal("failed to init postgres DB", zap.Error(err))
	}
	defer DB.Close()

	redisClient, err = redisInit.InitRedisClient(ctx, configMain.RedisCfg)
	if err != nil {
		zap.L().Fatal("failed to init redis client", zap.Error(err))
	}

	userStorage, err = storage.NewUserStorage(DB)
	if err != nil {
		zap.L().Fatal("failed to init user storage", zap.Error(err))
	}

	userSessionManager = storage.NewSessionManager(configMain.RedisCfg, redisClient)
	userJWTManager = storage.NewJWTManager(configMain.JwtCfg)

	controllerService = service.NewService(userStorage, userSessionManager, userJWTManager)

	code := m.Run()
	os.Exit(code)
}
