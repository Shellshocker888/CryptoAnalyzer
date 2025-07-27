package storage

import (
	"context"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/interfaces"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"
)

var _ interfaces.SessionManager = (*SessionManager)(nil)

type SessionManager struct {
	client     *redis.Client
	prefix     string
	expiration time.Duration
}

func InitRedisClient(ctx context.Context, cfg *config.RedisConfig) (*redis.Client, error) {

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.SessionDB,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return client, nil
}

func NewSessionManager(cfg *config.RedisConfig, client *redis.Client) *SessionManager {

	return &SessionManager{
		client:     client,
		prefix:     cfg.RefreshPrefix,
		expiration: cfg.RefreshExpiration,
	}
}

func (s *SessionManager) SaveRefreshToken(ctx context.Context, userID, refreshToken string) error {
	key := fmt.Sprintf("%s:%s:%s", s.prefix, userID, refreshToken)
	return s.client.Set(ctx, key, 1, s.expiration).Err()
}

func (s *SessionManager) IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error) {
	key := fmt.Sprintf("%s:%s:%s", s.prefix, userID, refreshToken)
	result, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check resreshToken: %s", err)
	}

	return result == 1, nil
}

func (s *SessionManager) DeleteRefreshToken(ctx context.Context, userID, refreshToken string) error {
	key := fmt.Sprintf("%s:%s:%s", s.prefix, userID, refreshToken)
	err := s.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete resreshToken: %s", err)
	}

	return nil
}

/*
type SessionManager interface {
	SaveRefreshToken(ctx context.Context, userID, refreshToken string) error
	RefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error)
	DeleteRefreshToken(ctx context.Context, userID, refreshToken string) error
}
*/
