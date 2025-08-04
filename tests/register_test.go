package tests

import (
	"crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/service"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
)

func TestRegisterWeakPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with weak password", func(t provider.T) {
		t.WithNewStep("Register with weak password", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "123123123"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Assert().ErrorIs(err, service.ErrWeakPassword)
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}

func TestRegisterStrongPasswordCorrectEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with strong password and correct email", func(t provider.T) {
		t.WithNewStep("Register with strong password and correct email", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Assert().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Assert().NotNil(resp, "Response не nil, регистрация выполнена")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})
	})
}

func TestRegisterEmailExists(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Register first time", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Ошибки нет, регистрация выполнена")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Register email exists", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "New12321_new"

			resp, err := authService.Register(ctx, registerRequest(username, email, password))

			sCtx.Assert().Error(err, "Ошибка, email уже существует")
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}

func TestRegisterWrongEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with wrong email", func(t provider.T) {
		t.WithNewStep("Register with wrong email", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemailgmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Assert().ErrorIs(err, service.ErrWeakEmail)
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}

func TestRegisterNoUsername(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register without username", func(t provider.T) {
		t.WithNewStep("Register without username", func(sCtx provider.StepCtx) {
			email := "newemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest("", email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Assert().ErrorIs(err, service.ErrNotEnoughData)
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}

func TestRegisterNoEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register without email", func(t provider.T) {
		t.WithNewStep("Register without email", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			password := "New12321_new"

			_, err := DB.Exec(`DELETE FROM users WHERE username = $1`, username)
			if err != nil {
				t.Logf("failed to delete user by username %s: %v", username, err)
			}

			var resp *auth.RegisterResponse
			resp, err = authService.Register(ctx, registerRequest(username, "", password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, "", resp)
			})

			sCtx.Assert().Error(err, "Ошибка, отсутствует email")
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}

func TestRegisterNoPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register without password", func(t provider.T) {
		t.WithNewStep("Register without password", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := authService.Register(ctx, registerRequest(username, email, ""))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Assert().Error(err, "Ошибка, пароль отсутствует")
			sCtx.Assert().Nil(resp, "Response nil, регистрация не выполнена")
		})
	})
}
