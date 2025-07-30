package interfaces

import "crypto_analyzer_auth_service/internal/domain"

type JWTManager interface {
	GenerateAccessToken(userID, username, email string) (string, error)
	GenerateRefreshToken() (string, error)
	ParseAccessToken(tokenStr string) (*domain.User, error) // возвращает userID
}
