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
		fmt.Printf("failed to init logger: %v", err)
		os.Exit(1)
	}
	defer logger.SyncLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = os.Setenv("APP_ENV", "test")
	if err != nil {
		logger.Log.Error("Error loading test env", zap.Error(err))
	}

	err = config.LoadConfig()
	if err != nil {
		fmt.Printf("failed to load config: %v", err)
		os.Exit(1)
	}

	var cfgPostgres *config.PostgresConfig
	cfgPostgres, err = config.LoadPostgresConfig()
	if err != nil {
		fmt.Printf("failed to load postgres config: %v", err)
		os.Exit(1)
	}

	DB, err = initPostgres(cfgPostgres)
	if err != nil {
		fmt.Printf("failed to init postgres DB: %v", err)
		os.Exit(1)
	}
	defer DB.Close()

	var cfgRedis *config.RedisConfig
	cfgRedis, err = config.LoadRedisConfig()
	if err != nil {
		fmt.Printf("failed to load redis config: %v", err)
		os.Exit(1)
	}

	redisClient, err = storage.InitRedisClient(ctx, cfgRedis)
	if err != nil {
		fmt.Printf("failed to init redis client: %v", err)
		os.Exit(1)
	}

	var cfgJWT *config.JWTConfig
	cfgJWT, err = config.LoadJWTConfig()
	if err != nil {
		fmt.Printf("failed to load JWT config: %v", err)
		os.Exit(1)
	}

	userStorage, err = storage.NewUserStorage(DB)
	if err != nil {
		fmt.Printf("failed to init user storage: %v", err)
		os.Exit(1)
	}

	userSessionManager = storage.NewSessionManager(cfgRedis, redisClient)
	userJWTManager = storage.NewJWTManager(cfgJWT)

	authService = service.NewService(userStorage, userSessionManager, userJWTManager)

	// Запускаем тесты
	code := m.Run()
	os.Exit(code)
}
