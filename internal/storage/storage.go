package storage

import (
	"crypto_analyzer_auth_service/internal/config/model"
	"database/sql"
	"github.com/redis/go-redis/v9"
	"time"
)

var (
	_ JWTManagerInterface     = (*JWTManager)(nil)
	_ UsersStorageInterface   = (*UserPostgresStorage)(nil)
	_ SessionManagerInterface = (*SessionManager)(nil)
)

type JWTManager struct {
	secretKey         []byte
	accessTokenTTL    time.Duration
	refreshTokenBytes int
}

type SessionManager struct {
	client     *redis.Client
	prefix     string
	expiration time.Duration
}

type UserPostgresStorage struct {
	DB *sql.DB
}

func NewJWTManager(cfg *model.JwtConfig) *JWTManager {
	return &JWTManager{
		secretKey:         cfg.SecretKey,
		accessTokenTTL:    cfg.AccessTokenTTL,
		refreshTokenBytes: cfg.RefreshTokenBytes,
	}
}

func NewSessionManager(cfg *model.RedisConfig, client *redis.Client) *SessionManager {

	return &SessionManager{
		client:     client,
		prefix:     cfg.RefreshPrefix,
		expiration: cfg.RefreshExpiration,
	}
}

func NewUserStorage(db *sql.DB) (*UserPostgresStorage, error) {
	return &UserPostgresStorage{DB: db}, nil
}
