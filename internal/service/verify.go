package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/infrastructure/logger"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func (s *ControllerService) Verify(ctx context.Context, req *auth.VerifyRequest) (*auth.VerifyResponse, error) {
	log := logger.FromContext(ctx)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Warn("no access token", zap.Error(domain.ErrNoAccessToken))
		return nil, domain.ErrNoAccessToken
	}

	accessTokenSlice := md.Get("authorization")
	if len(accessTokenSlice) == 0 || accessTokenSlice[0] == "" {
		log.Warn("no access token", zap.Error(domain.ErrNoAccessToken))
		return nil, domain.ErrNoAccessToken
	}
	accessToken := accessTokenSlice[0]

	user, err := s.JWTManager.ParseAccessToken(accessToken)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidAccessToken) {
			log.Error("invalid access token", zap.Error(err))
			return nil, fmt.Errorf("invalid access token: %w", err)
		}
		log.Error("failed to parse access token", zap.Error(err))
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	if user == nil {
		log.Error("nil user", zap.Error(domain.ErrNilUser))
		return nil, domain.ErrNilUser
	}

	return &auth.VerifyResponse{
		UserId:   user.ID,
		Email:    user.Email,
		Username: user.Username,
	}, nil
}
