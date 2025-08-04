package tests

import (
	"context"
	"crypto_analyzer_auth_service/gen/go"
	pb "crypto_analyzer_auth_service/gen/go"
	"testing"
	"time"
)

func newTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Очищает пользователя по email
func cleanUserByEmail(ctx context.Context, t *testing.T, email string, resp *auth.RegisterResponse) {
	if email != "" {
		if _, err := DB.Exec(`DELETE FROM users WHERE email = $1`, email); err != nil {
			t.Logf("failed to delete user by email %s: %v", email, err)
		}
	}

	if resp != nil {
		if err := userSessionManager.DeleteRefreshToken(ctx, resp.RefreshToken); err != nil {
			t.Logf("failed to delete refresh token: %v", err)
		}
	}
}

func loginRequest(username, email, password string) *pb.LoginRequest {
	return &pb.LoginRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

func registerRequest(username, email, password string) *pb.RegisterRequest {
	return &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

func refreshRequest(refreshToken string) *pb.RefreshRequest {
	return &pb.RefreshRequest{RefreshToken: refreshToken}
}
