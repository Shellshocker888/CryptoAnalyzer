package service

import (
	"crypto_analyzer_auth_service/internal/storage"
)

type ControllerService struct {
	Storage    storage.UsersStorageInterface
	Session    storage.SessionManagerInterface
	JWTManager storage.JWTManagerInterface
}

func NewService(storage storage.UsersStorageInterface, session storage.SessionManagerInterface, JWTManager storage.JWTManagerInterface) *ControllerService {
	return &ControllerService{
		Storage:    storage,
		Session:    session,
		JWTManager: JWTManager,
	}
}
