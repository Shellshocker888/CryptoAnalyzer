package domain

import "errors"

var (
	ErrWeakPassword       = errors.New("password must be at least 8 characters long, contain uppercase and lowercase letters, at least one digit, and a special character")
	ErrWeakEmail          = errors.New("invalid email format")
	ErrNotEnoughData      = errors.New("username or/and email must be provided, password must not be empty")
	ErrRefreshFailed      = errors.New("failed to refresh token")
	ErrInvalidAccessToken = errors.New("access token is invalid")
	ErrNoAccessToken      = errors.New("no access token")
	ErrNoRefreshToken     = errors.New("no refresh token")
	ErrNilUser            = errors.New("user is nil")
	ErrNoSuchRefreshToken = errors.New("refresh token not found")
)
