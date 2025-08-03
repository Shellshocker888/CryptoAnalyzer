package tests

import (
	"context"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/logger"
	"crypto_analyzer_auth_service/internal/service"
	"crypto_analyzer_auth_service/internal/storage"
	"database/sql"
	"fmt"
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
	authService        *service.AuthService
)

func initPostgres(cfg *config.PostgresConfig) (*sql.DB, error) {

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SslMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(1 * time.Hour)

	return db, nil
}

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

	if err = config.LoadConfig(); err != nil {
		zap.L().Fatal("failed to load config", zap.Error(err))
	}

	var cfgPostgres *config.PostgresConfig
	cfgPostgres, err = config.LoadPostgresConfig()
	if err != nil {
		zap.L().Fatal("failed to load postgres config", zap.Error(err))
	}

	DB, err = initPostgres(cfgPostgres)
	if err != nil {
		zap.L().Fatal("failed to init postgres DB", zap.Error(err))
	}
	defer DB.Close()

	var cfgRedis *config.RedisConfig
	cfgRedis, err = config.LoadRedisConfig()
	if err != nil {
		zap.L().Fatal("failed to load redis config", zap.Error(err))
	}

	redisClient, err = storage.InitRedisClient(ctx, cfgRedis)
	if err != nil {
		zap.L().Fatal("failed to init redis client", zap.Error(err))
	}

	var cfgJWT *config.JWTConfig
	cfgJWT, err = config.LoadJWTConfig()
	if err != nil {
		zap.L().Fatal("failed to load JWT config", zap.Error(err))
	}

	userStorage, err = storage.NewUserStorage(DB)
	if err != nil {
		zap.L().Fatal("failed to init user storage", zap.Error(err))
	}

	userSessionManager = storage.NewSessionManager(cfgRedis, redisClient)
	userJWTManager = storage.NewJWTManager(cfgJWT)

	authService = service.NewService(userStorage, userSessionManager, userJWTManager)

	code := m.Run()
	os.Exit(code)
}
