package tests

import (
	"crypto_analyzer_auth_service/gen/go"
	pb "crypto_analyzer_auth_service/gen/go"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
)

func TestRegisterWeakPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with weak password", func(t provider.T) {
		t.WithNewStep("Weak password", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "123123123"

			cleanUserByEmail(ctx, tt, email, "")

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
				cleanUserByEmail(ctx, tt, email, refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка при слабом пароле")
			sCtx.Assert().Nil(resp, "Response nil, так как регистрация неуспешна")
		})
	})
}

func TestRegisterStrongPasswordCorrectEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with strong password and correct email", func(t provider.T) {
		t.WithNewStep("Strong password and correct email", func(sCtx provider.StepCtx) {
			username := "Shellshocker25"
			email := "newemail25@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, "")

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
				cleanUserByEmail(ctx, tt, email, refreshToken)
			})

			sCtx.Assert().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Assert().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")
		})
	})
}

func TestRegisterEmailExists(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Email exists", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, "")

			resp, err := authService.Register(ctx, &pb.RegisterRequest{
				Username: username,
				Email:    email,
				Password: password,
			})

			sCtx.Assert().NoError(err, "Ошибки нет, регистрация успешна")
			sCtx.Assert().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Assert().NotEmpty(resp.RefreshToken, "Наличие refresh токена")

			resp, err = authService.Register(ctx, &pb.RegisterRequest{
				Username: username,
				Email:    email,
				Password: password,
			})

			t.Cleanup(func() {
				var refreshToken string
				if resp != nil {
					refreshToken = resp.RefreshToken
				}
				cleanUserByEmail(ctx, tt, email, refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка, email уже существует")
			sCtx.Assert().Nil(resp, "Response nil, регистрация неуспешна")
		})
	})
}

func TestRegisterWrongEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Email exists", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemailgmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, "")

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
				cleanUserByEmail(ctx, tt, email, refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка регистрации, email отсутствует")
			sCtx.Assert().Nil(resp, "Response nil, регистрация неуспешна")
		})
	})
}

func TestRegisterNoUsername(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Email exists", func(sCtx provider.StepCtx) {
			email := "newemail@gmail.com"
			password := "New12321_new"

			cleanUserByEmail(ctx, tt, email, "")

			resp, err := authService.Register(ctx, &pb.RegisterRequest{
				Username: "",
				Email:    email,
				Password: password,
			})

			t.Cleanup(func() {
				var refreshToken string
				if resp != nil {
					refreshToken = resp.RefreshToken
				}
				cleanUserByEmail(ctx, tt, email, refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка, отсутствует username")
			sCtx.Assert().Nil(resp, "Response nil, регистрация неуспешна")
		})
	})
}

func TestRegisterNoEmail(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Email exists", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			password := "New12321_new"

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

			t.Cleanup(func() {
				var refreshToken string
				if resp != nil {
					refreshToken = resp.RefreshToken
				}
				cleanUserByEmail(ctx, tt, "", refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка, отсутствует email")
			sCtx.Assert().Nil(resp, "Response nil, регистрация неуспешна")
		})
	})
}

func TestRegisterNoPassword(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Register with email exists", func(t provider.T) {
		t.WithNewStep("Email exists", func(sCtx provider.StepCtx) {
			username := "Shellshocker"
			email := "newemail@gmail.com"

			cleanUserByEmail(ctx, tt, email, "")

			resp, err := authService.Register(ctx, &pb.RegisterRequest{
				Username: username,
				Email:    email,
				Password: "",
			})
			t.Cleanup(func() {
				var refreshToken string
				if resp != nil {
					refreshToken = resp.RefreshToken
				}
				cleanUserByEmail(ctx, tt, "", refreshToken)
			})

			sCtx.Assert().Error(err, "Ошибка, пароль отсутствует")
			sCtx.Assert().Nil(resp, "Response nil, регистрация неуспешна")
		})
	})
}
