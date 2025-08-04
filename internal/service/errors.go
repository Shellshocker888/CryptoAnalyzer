package service

import "errors"

var (
	ErrWeakPassword   = errors.New("password must be at least 8 characters long, contain uppercase and lowercase letters, at least one digit, and a special character")
	ErrWeakEmail      = errors.New("invalid email format")
	ErrNotEnoughData  = errors.New("username or email must be provided and password must not be empty")
	ErrInvCredentials = errors.New("invalid credentials")
	ErrRefreshFailed  = errors.New("failed to refresh token")
)
