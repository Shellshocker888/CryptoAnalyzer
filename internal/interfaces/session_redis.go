package interfaces

import "context"

type SessionManager interface {
	SaveRefreshToken(ctx context.Context, userID, refreshToken string) error
	IsRefreshTokenValid(ctx context.Context, userID, refreshToken string) (bool, error)
	DeleteRefreshToken(ctx context.Context, userID, refreshToken string) error
}
