package tests

import (
	"crypto_analyzer_auth_service/internal/domain"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
	"time"
)

func TestRefreshValidRefreshToken(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Refresh with valid refresh token", func(t provider.T) {
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

		t.WithNewStep("Refresh with valid refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Refresh(ctx, refreshRequest(refreshToken))

			sCtx.Assert().NoError(err, "Отсутствие ошибки, refresh token valid")
			sCtx.Assert().NotNil(resp, "Response не nil, refresh выполнен")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
			sCtx.Assert().NotEqual(refreshToken, resp.RefreshToken, "Старый refreshToken не равен новому - обновлен")
		})
	})
}

func TestRefreshInvalidRefreshToken(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Refresh with invalid refresh token", func(t provider.T) {

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

		t.WithNewStep("Refresh with invalid refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Refresh(ctx, refreshRequest("invalidRefreshToken"))

			sCtx.Assert().ErrorIs(err, domain.ErrNoSuchRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil, refresh не выполнен")
		})
	})
}

func TestRefreshValidRefreshTokenWithoutUser(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Refresh with valid refresh token without user saved", func(t provider.T) {
		var refreshToken string

		t.WithNewStep("Register", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			refreshToken = resp.RefreshToken

			cleanUserByEmail(ctx, tt, email, resp)

			sCtx.Require().NoError(err, "Отсутствие ошибки, данные корректны")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Refresh with valid refresh token without user saved", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Refresh(ctx, refreshRequest(refreshToken))

			sCtx.Assert().ErrorIs(err, domain.ErrNoSuchRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil, refresh не выполнен")
		})
	})
}

func TestRefreshOutdatedRefreshToken(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Refresh with outdated refresh token", func(t provider.T) {
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

		t.WithNewStep("Refresh with outdated refresh token", func(sCtx provider.StepCtx) {
			time.Sleep(2 * time.Second)

			resp, err := controllerService.Refresh(ctx, refreshRequest(refreshToken))

			sCtx.Assert().ErrorIs(err, domain.ErrNoSuchRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil, refresh не выполнен")
		})
	})
}

func TestRefreshWithoutRefreshToken(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Refresh without refresh token", func(t provider.T) {

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

		t.WithNewStep("Refresh without refresh token", func(sCtx provider.StepCtx) {
			resp, err := controllerService.Refresh(ctx, refreshRequest(""))

			sCtx.Assert().ErrorIs(err, domain.ErrNoRefreshToken)
			sCtx.Assert().Nil(resp, "Response nil, refresh не выполнен")
		})
	})
}
