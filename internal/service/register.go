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
	if req.Username == "" {
		return nil, errors.New("username is required")
	}
	if req.Email == "" {
		return nil, errors.New("email is required")
	}
	if !isValidEmail(req.Email) {
		return nil, errors.New("invalid email format")
	}
	if req.Password == "" {
		return nil, errors.New("password is required")
	}
	if !isValidPassword(req.Password) {
		return nil, errors.New("password must be at least 8 characters long, contain uppercase and lowercase letters, at least one digit, and a special character")
	}

	exists, err := s.Storage.EmailExists(ctx, req.Email)
	if err != nil {
		logger.Log.Error("failed to check email existence", zap.Error(err))
		return nil, errors.New("failed to register user")
	}
	if exists {
		return nil, errors.New("the email has been already taken")
	}

	exists, err = s.Storage.UsernameExists(ctx, req.Username)
	if err != nil {
		logger.Log.Error("failed to check username existence", zap.Error(err))
		return nil, errors.New("failed to register user")
	}
	if exists {
		return nil, errors.New("the username has been already taken")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Error("failed to generate password hash", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	userID := uuid.New().String()

	user := &domain.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
	}

	err = s.Storage.CreateUser(ctx, user)
	if err != nil {
		logger.Log.Error("failed to save user", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	accessToken, err := s.JWTManager.GenerateAccessToken(userID, req.Username, req.Email)
	if err != nil {
		logger.Log.Error("failed to generate access token", zap.Error(err))
		return nil, errors.New("failed to register user")
	}

	refreshToken, err := s.JWTManager.GenerateRefreshToken()
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
