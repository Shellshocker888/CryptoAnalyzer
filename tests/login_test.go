package tests

import (
	"crypto_analyzer_auth_service/internal/domain"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
)

func TestLoginWeakPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login with weak password", func(t provider.T) {
		t.WithNewStep("Login with weak password", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "123123123"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().ErrorIs(err, domain.ErrWeakPassword)
			sCtx.Assert().Nil(resp, "Response nil, вход не выполнен")
		})
	})
}

func TestLoginStrongPasswordCorrectEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login with strong password and correct email", func(t provider.T) {
		t.WithNewStep("Register with strong password and correct email", func(sCtx provider.StepCtx) {
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

		t.WithNewStep("Login with strong password and correct email", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Assert().NotNil(resp, "Response не nil, вход выполнен")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})
	})
}

func TestLoginWeakEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login with wrong email", func(t provider.T) {
		t.WithNewStep("Login with wrong email", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemailgmail.com"
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().ErrorIs(err, domain.ErrWeakEmail)
			sCtx.Assert().Nil(resp, "Response nil, вход не выполнен")
		})
	})
}

func TestLoginNoUsernameValidEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login without username", func(t provider.T) {
		t.WithNewStep("Register with all data", func(sCtx provider.StepCtx) {
			username := "testUsername"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки всех корректных данных")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Login without username", func(sCtx provider.StepCtx) {
			username := ""
			email := "newemail25@gmail.com"
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().NoError(err, "Отсутствие ошибки при наличии email")
			sCtx.Assert().NotNil(resp, "Response не nil, вход выполнен")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})
	})
}

func TestLoginNoEmailValidUsername(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login without email", func(t provider.T) {
		t.WithNewStep("Register with all data", func(sCtx provider.StepCtx) {
			username := "testUsername"
			email := "testemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки всех корректных данных")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Login without email", func(sCtx provider.StepCtx) {
			username := "testUsername"
			email := ""
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().NoError(err, "Отсутствие ошибки при наличии email")
			sCtx.Assert().NotNil(resp, "Response не nil, вход выполнен")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})
	})
}

func TestLoginNoPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login without password", func(t provider.T) {
		t.WithNewStep("Login without password", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, ""))

			sCtx.Assert().ErrorIs(err, domain.ErrNotEnoughData)
			sCtx.Assert().Nil(resp, "Response nil, вход не выполнен")
		})
	})
}

func TestLoginNoEmailInvalidUsername(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login with invalid username", func(t provider.T) {
		t.WithNewStep("Register with all data", func(sCtx provider.StepCtx) {
			username := "testUsername"
			email := "testemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки, все данные корректны")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Login without email and with invalid username", func(sCtx provider.StepCtx) {
			username := "invalidUsername"
			email := ""
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().ErrorIs(err, domain.ErrNilUser)
			sCtx.Assert().Nil(resp, "Response nil, вход не выполнен")
		})
	})
}

func TestLoginNoUsernameInvalidEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Login with invalid email", func(t provider.T) {
		t.WithNewStep("Register with all data", func(sCtx provider.StepCtx) {
			username := "testUsername"
			email := "testemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки, все данные корректны")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})

		t.WithNewStep("Login without username and with invalid email", func(sCtx provider.StepCtx) {
			username := ""
			email := "123qwe@gmail.com"
			password := "New12321_new"

			resp, err := controllerService.Login(ctx, loginRequest(username, email, password))

			sCtx.Assert().ErrorIs(err, domain.ErrNilUser)
			sCtx.Assert().Nil(resp, "Response nil, вход не выполнен")
		})
	})
}
