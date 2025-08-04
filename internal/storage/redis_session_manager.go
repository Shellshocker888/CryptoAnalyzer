package storage

import (
	"context"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/interfaces"
	"errors"
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
	key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
	return s.client.Set(ctx, key, userID, s.expiration).Err()
}

func (s *SessionManager) GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
	userID, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", errors.New("refresh token not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get userID by refresh token: %w", err)
	}
	return userID, nil
}

/*
	func (s *SessionManager) IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error) {
		key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
		storedUserID, err := s.client.Get(ctx, key).Result()

		if errors.Is(err, redis.Nil) {
			return false, nil
		}

		if err != nil {
			return false, fmt.Errorf("failed to get refresh token: %w", err)
		}

		return storedUserID == userID, nil
	}
*/
func (s *SessionManager) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}
