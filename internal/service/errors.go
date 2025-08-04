package service

import "errors"

var ErrWeakPassword = errors.New("password must be at least 8 characters long, contain uppercase and lowercase letters, at least one digit, and a special character")

var ErrWeakEmail = errors.New("invalid email format")

var ErrNotEnoughData = errors.New("username or email must be provided and password must not be empty")

var ErrInvCredentials = errors.New("invalid credentials")
