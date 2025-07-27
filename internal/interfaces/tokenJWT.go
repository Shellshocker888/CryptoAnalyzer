package interfaces

type JWTManager interface {
	GenerateAccessToken(userID string) (string, error)
	GenerateRefreshToken() (string, error)
	ParseAccessToken(token string) (string, error) // возвращает userID
}
