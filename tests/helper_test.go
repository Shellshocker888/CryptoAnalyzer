package tests

import (
	"context"
	"testing"
	"time"
)

func newTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Очищает пользователя по email
func cleanUserByEmail(ctx context.Context, t *testing.T, email, refreshToken string) {
	if email != "" {
		if _, err := DB.Exec(`DELETE FROM users WHERE email = $1`, email); err != nil {
			t.Logf("failed to delete user by email %s: %v", email, err)
		}
	}

	if refreshToken != "" {
		if err := userSessionManager.DeleteRefreshToken(ctx, refreshToken); err != nil {
			t.Logf("failed to delete refresh token: %v", err)
		}
	}
}
