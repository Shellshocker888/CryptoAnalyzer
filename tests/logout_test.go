package tests

import (
	"crypto_analyzer_auth_service/internal/domain"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
)

func TestLogoutValidRefresh(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Logout with valid refresh token", func(t provider.T) {
		var refreshToken string

		t.WithNewStep("Register", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")

			refreshToken = resp.RefreshToken
		})

		t.WithNewStep("Logout with valid refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Logout(ctx, logoutRequest(refreshToken))

			sCtx.Assert().NoError(err, "Отсутствие ошибки, refresh token valid")
			sCtx.Assert().NotNil(resp, "Response не nil, logout выполнен")
		})
	})
}

func TestLogoutInvalidRefresh(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Logout with invalid refresh token", func(t provider.T) {

		t.WithNewStep("Register", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Logout with invalid refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Logout(ctx, logoutRequest("invalidRefreshToken"))

			sCtx.Assert().ErrorIs(err, domain.ErrNoSuchRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil")
		})
	})
}

func TestLogoutWithoutRefresh(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Logout without refresh token", func(t provider.T) {

		t.WithNewStep("Register", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Logout without refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Logout(ctx, logoutRequest(""))

			sCtx.Assert().ErrorIs(err, domain.ErrNoRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil")
		})
	})
}
