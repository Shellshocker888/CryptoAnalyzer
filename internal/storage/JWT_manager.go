package storage

import (
	"crypto/rand"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/interfaces"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var _ interfaces.JWTManager = (*JWTManager)(nil)

type JWTManager struct {
	secretKey         []byte
	accessTokenTTL    time.Duration
	refreshTokenBytes int
}

func NewJWTManager(cfg *config.JWTConfig) *JWTManager {
	return &JWTManager{
		secretKey:         cfg.SecretKey,
		accessTokenTTL:    cfg.AccessTokenTTL,
		refreshTokenBytes: cfg.RefreshTokenBytes,
	}
}

func (j *JWTManager) GenerateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(j.accessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return accessToken.SignedString(j.secretKey)
}

func (j *JWTManager) GenerateRefreshToken() (string, error) {
	byteSlice := make([]byte, j.refreshTokenBytes)
	_, err := rand.Read(byteSlice)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(byteSlice), nil
}

func (j *JWTManager) ParseAccessToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.secretKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("access token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("user_id is not found in access token")
	}

	return userID, nil
}

/*
type JWTManager interface {
    GenerateAccessToken(userID string) (string, error)
    GenerateRefreshToken() (string, error)
    ParseAccessToken(token string) (string, error) // возвращает userID
}
*/
