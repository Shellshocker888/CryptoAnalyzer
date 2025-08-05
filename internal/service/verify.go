package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/errors_my"
	"crypto_analyzer_auth_service/internal/logger"
	"errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func (s *AuthService) Verify(ctx context.Context, req *auth.VerifyRequest) (*auth.VerifyResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Info("no access token to verify")
		return nil, errors_my.ErrNoAccessToken
	}

	accessTokenSlice := md.Get("authorization")
	if len(accessTokenSlice) == 0 || accessTokenSlice[0] == "" {
		logger.Log.Info("no access token to verify")
		return nil, errors_my.ErrNoAccessToken
	}
	accessToken := accessTokenSlice[0]

	user, err := s.JWTManager.ParseAccessToken(accessToken)
	if err != nil {
		if err.Error() == "access token is invalid" {
			logger.Log.Error("access token is invalid", zap.Error(err))
			return nil, errors_my.ErrInvalidAccessToken
		}
		logger.Log.Error("failed to parse access token", zap.Error(err))
		return nil, errors.New("failed to verify token")
	}

	if user == nil {
		logger.Log.Error("parsed user is nil")
		return nil, errors.New("failed to verify token")
	}

	return &auth.VerifyResponse{
		UserId:   user.ID,
		Email:    user.Email,
		Username: user.Username,
	}, nil
}
