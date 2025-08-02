package tests

import (
	"context"
	"crypto_analyzer_auth_service/gen/go"
	pb "crypto_analyzer_auth_service/gen/go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRegisterWeakPassword(t *testing.T) {
	username := "Shellshocker"
	email := "newemail@gmail.com"
	password := "123123123"

	ctx := newTestContext(t)

	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, email, refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestRegisterStrongPasswordGoodEmail(t *testing.T) {
	username := "Shellshocker25"
	email := "newemail25@gmail.com"
	password := "New12321_new"

	ctx := newTestContext(t)
	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	})

	t.Cleanup(func() {
		var refreshToken string
		if resp != nil {
			refreshToken = resp.RefreshToken
		}
		cleanUserByEmail(ctx, t, email, refreshToken)
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)
}

func TestRegisterEmailExists(t *testing.T) {
	username := "Shellshocker"
	email := "newemail@gmail.com"
	password := "New12321_new"

	ctx := newTestContext(t)
	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	})

	require.NoError(t, err)
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)

	resp, err = authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, email, refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestRegisterWrongEmail(t *testing.T) {
	username := "Shellshocker"
	email := "newemailgmail.com"
	password := "New12321_new"

	ctx := newTestContext(t)
	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, email, refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestRegisterNoUsername(t *testing.T) {
	email := "newemail@gmail.com"
	password := "New12321_new"

	ctx := newTestContext(t)
	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: "",
		Email:    email,
		Password: password,
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, email, refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestRegisterNoEmail(t *testing.T) {
	username := "Shellshocker"
	password := "New12321_new"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	_, err := DB.Exec(`DELETE FROM users WHERE username = $1`, username)
	if err != nil {
		t.Logf("failed to delete user by username %s: %v", username, err)
	}

	var resp *auth.RegisterResponse
	resp, err = authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    "",
		Password: password,
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, "", refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestRegisterNoPassword(t *testing.T) {
	username := "Shellshocker"
	email := "newemail@gmail.com"

	ctx := newTestContext(t)
	cleanUserByEmail(ctx, t, email, "")

	resp, err := authService.Register(ctx, &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: "",
	})
	if err == nil {
		t.Cleanup(func() {
			var refreshToken string
			if resp != nil {
				refreshToken = resp.RefreshToken
			}
			cleanUserByEmail(ctx, t, "", refreshToken)
		})
	}

	require.Error(t, err)
	require.Nil(t, resp)
}
