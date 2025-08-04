package service

import (
	"context"
	auth "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/logger"
	"errors"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"time"
	"unicode"
)

func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func isValidEmail(email string) bool {
	// Очень простое регулярное выражение для примера, можно заменить на более точное
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func (s *AuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	username := req.Username
	email := req.Email
	password := req.Password

	if username == "" || email == "" || password == "" {
		return nil, ErrNotEnoughData
	}

	if !isValidEmail(email) {
		return nil, ErrWeakEmail
	}

	if !isValidPassword(password) {
		return nil, ErrWeakPassword
	}

	exists, err := s.Storage.EmailExists(ctx, email)
	if err != nil {
		logger.Log.Error("failed to check email existence", zap.Error(err))
		return nil, errors.New("failed to register user")
	}
	if exists {
		return nil, errors.New("the email has been already taken")
	}

	/*exists, err = s.Storage.UsernameExists(ctx, req.Username)
	if err != nil {
		logger.Log.Error("failed to check username existence", zap.Error(err))
		return nil, errors.New("failed to register user")
	}
	if exists {
		return nil, errors.New("the username has been already taken")
	}*/

	var passwordHash []byte
	passwordHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Error("failed to generate password hash", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	userID := uuid.New().String()

	user := &domain.User{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
	}

	err = s.Storage.CreateUser(ctx, user)
	if err != nil {
		logger.Log.Error("failed to save user", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	var accessToken string
	accessToken, err = s.JWTManager.GenerateAccessToken(userID, username, email)
	if err != nil {
		logger.Log.Error("failed to generate access token", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	var refreshToken string
	refreshToken, err = s.JWTManager.GenerateRefreshToken()
	if err != nil {
		logger.Log.Error("failed to generate refresh token", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	err = s.Session.SaveRefreshToken(ctx, userID, refreshToken)
	if err != nil {
		logger.Log.Error("failed to save refresh token session", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	return &auth.RegisterResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}, nil
}
