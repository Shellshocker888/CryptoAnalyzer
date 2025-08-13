package tests

import (
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"testing"
)

func TestVerifyValidAccessToken(tt *testing.T) {
	ctx := newTestContext(tt)

	var accessToken string

	username := "Shellshocker25"
	email := "newemail25@gmail.com"
	password := "New12321_new"

	runner.Run(tt, "Verify with valid access token", func(t provider.T) {
		t.WithNewStep("Register", func(sCtx provider.StepCtx) {

			cleanUserByEmail(ctx, tt, email, nil)

			resp, err := controllerService.Register(ctx, registerRequest(username, email, password))

			t.Cleanup(func() {
				cleanUserByEmail(ctx, tt, email, resp)
			})

			sCtx.Require().NoError(err, "Отсутствие ошибки при сильном пароле и корректном email")
			sCtx.Require().NotNil(resp, "Response не nil, регистрация успешна")
			sCtx.Require().NotEmpty(resp.Token, "Наличие access токена")
			sCtx.Require().NotEmpty(resp.RefreshToken, "Наличие refresh токена")

			accessToken = resp.GetToken()
		})

		t.WithNewStep("Verify with valid access token", func(sCtx provider.StepCtx) {

			resp, err := verifyRequest(accessToken)

			sCtx.Assert().NoError(err, "Отсутствие ошибки,valid access token")
			sCtx.Assert().NotNil(resp, "Response не nil")
			sCtx.Assert().Equal(username, resp.Username, "Соответствие исходному username")
			sCtx.Assert().Equal(email, resp.Email, "Соответствие исходному email")
			sCtx.Assert().NotEmpty(resp.UserId, "Наличие UserId")
		})
	})
}

func TestVerifyInvalidAccessToken(tt *testing.T) {
	runner.Run(tt, "Verify with invalid access token", func(t provider.T) {
		t.WithNewStep("Verify with invalid access token", func(sCtx provider.StepCtx) {

			resp, err := verifyRequest("2e2qweadwqdawdwff")

			sCtx.Assert().Error(err, "Ошибка, invalid access token")
			sCtx.Assert().Nil(resp, "Response nil")
		})
	})
}

func TestVerifyEmptyAccessToken(tt *testing.T) {
	runner.Run(tt, "Verify with empty access token", func(t provider.T) {
		t.WithNewStep("Verify with empty access token", func(sCtx provider.StepCtx) {

			resp, err := verifyRequest("")

			sCtx.Assert().ErrorIs(err, domain.ErrNoAccessToken)
			sCtx.Assert().Nil(resp, "Response nil")
		})
	})
}

func TestVerifyWithoutAccessToken(tt *testing.T) {
	ctx := newTestContext(tt)

	runner.Run(tt, "Verify without access token", func(t provider.T) {
		t.WithNewStep("Verify without access token", func(sCtx provider.StepCtx) {

			resp, err := controllerService.Verify(ctx, &pb.VerifyRequest{})

			sCtx.Assert().ErrorIs(err, domain.ErrNoAccessToken)
			sCtx.Assert().Nil(resp, "Response nil")
		})
	})
}
