package storage

import (
	"context"
	"crypto_analyzer_auth_service/internal/domain"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
)

type SessionManagerInterface interface {
	SaveRefreshToken(ctx context.Context, userID, refreshToken string) error
	GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (string, error)
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	//IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error)
}

func (s *SessionManager) SaveRefreshToken(ctx context.Context, userID, refreshToken string) error {
	key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
	if err := s.client.Set(ctx, key, userID, s.expiration).Err(); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	return nil
}

func (s *SessionManager) GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
	userID, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", domain.ErrNoSuchRefreshToken
	}
	if err != nil {
		return "", fmt.Errorf("failed to get userID: %w", err)
	}
	return userID, nil
}

/*
	func (s *SessionManager) IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error) {
		key := fmt.Sprintf("%s:%s", s.prefix, refreshToken)
		storedUserID, err := s.client.Get(ctx, key).Result()

		if errors_my.Is(err, redis.Nil) {
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
	deleted, err := s.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	if deleted == 0 {
		return domain.ErrNoSuchRefreshToken
	}
	return nil
}
