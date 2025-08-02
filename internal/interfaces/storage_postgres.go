package interfaces

import (
	"context"
	"crypto_analyzer_auth_service/internal/domain"
)

type UsersStorage interface {
	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByUsernameEmail(ctx context.Context, username, email string) (*domain.User, error)
	GetUserByUserID(ctx context.Context, userID string) (*domain.User, error)
	EmailExists(ctx context.Context, email string) (bool, error)
	//UsernameExists(ctx context.Context, username string) (bool, error)
}
