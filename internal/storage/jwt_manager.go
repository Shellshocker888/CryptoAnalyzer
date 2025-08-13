package storage

import (
	"crypto/rand"
	"crypto_analyzer_auth_service/internal/domain"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JWTManagerInterface interface {
	GenerateAccessToken(userID, username, email string) (string, error)
	GenerateRefreshToken() (string, error)
	ParseAccessToken(tokenStr string) (*domain.User, error) // возвращает userID
}

func (j *JWTManager) GenerateAccessToken(userID, username, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"email":    email,
		"exp":      time.Now().Add(j.accessTokenTTL).Unix(),
		"iat":      time.Now().Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessTokenSigned, err := accessToken.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("error to generate access token: %w", err)
	}

	return accessTokenSigned, nil
}

func (j *JWTManager) GenerateRefreshToken() (string, error) {
	byteSlice := make([]byte, j.refreshTokenBytes)
	_, err := rand.Read(byteSlice)
	if err != nil {
		return "", fmt.Errorf("error to generate refresh token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(byteSlice), nil
}

func (j *JWTManager) ParseAccessToken(tokenStr string) (*domain.User, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error to parse access token: %w", err)
	}

	if !token.Valid {
		return nil, domain.ErrInvalidAccessToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	var userID string
	userID, ok = claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("user_id has been not found in access token")
	}

	var username string
	username, ok = claims["username"].(string)
	if !ok {
		return nil, fmt.Errorf("username has been not found in access token")
	}

	var email string
	email, ok = claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("email has been not found in access token")
	}

	user := &domain.User{
		ID:       userID,
		Username: username,
		Email:    email,
	}

	return user, nil
}

/*
type JWTManager interface {
    GenerateAccessToken(userID string) (string, error)
    GenerateRefreshToken() (string, error)
    ParseAccessToken(token string) (string, error) // возвращает userID
}
*/
