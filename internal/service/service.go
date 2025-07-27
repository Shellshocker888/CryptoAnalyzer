package service

import (
	"crypto_analyzer_auth_service/internal/interfaces"
)

type AuthService struct {
	Storage    interfaces.UsersStorage
	Session    interfaces.SessionManager
	JWTManager interfaces.JWTManager
}

func NewService(storage interfaces.UsersStorage, session interfaces.SessionManager, JWTManager interfaces.JWTManager) *AuthService {
	return &AuthService{
		Storage:    storage,
		Session:    session,
		JWTManager: JWTManager,
	}
}
