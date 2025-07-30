package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/logger"
	"errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func (s *AuthService) Verify(ctx context.Context, req *auth.VerifyRequest) (*auth.VerifyResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Error("no incoming metadata")
		return nil, errors.New("no incoming metadata")
	}

	accessTokenSlice := md.Get("authorization")
	if len(accessTokenSlice) == 0 || accessTokenSlice[0] == "" {
		logger.Log.Error("authorization token is missing in metadata")
		return nil, errors.New("failed to verify credentials")
	}
	accessToken := accessTokenSlice[0]

	user, err := s.JWTManager.ParseAccessToken(accessToken)
	if err != nil {
		if err.Error() == "access token is invalid" {
			logger.Log.Error("access token is invalid", zap.Error(err))
			return nil, errors.New("access token is invalid")
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
