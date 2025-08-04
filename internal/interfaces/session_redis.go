package interfaces

import "context"

type SessionManager interface {
	SaveRefreshToken(ctx context.Context, userID, refreshToken string) error
	GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (string, error)
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	//IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error)
}
