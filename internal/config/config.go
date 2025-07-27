package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"strconv"
	"time"
)

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SslMode  string
}

type RedisConfig struct {
	Addr              string
	Password          string
	SessionDB         int
	RefreshPrefix     string
	RefreshExpiration time.Duration
}

type JWTConfig struct {
	SecretKey         []byte
	AccessTokenTTL    time.Duration
	RefreshTokenBytes int
}

func getEnv(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("failed to load env %s", key)
	}

	return val, nil
}

func LoadConfig() error {
	err := godotenv.Load()
	if err != nil {
		return fmt.Errorf("failed to load env: %w", err)
	}

	return nil
}

func LoadPostgresConfig() (*PostgresConfig, error) {
	cfg := &PostgresConfig{}

	var err error
	cfg.Host, err = getEnv("DB_HOST")
	if err != nil {
		return nil, err
	}
	cfg.Port, err = getEnv("DB_PORT")
	if err != nil {
		return nil, err
	}

	cfg.User, err = getEnv("DB_USER")
	if err != nil {
		return nil, err
	}

	cfg.Password, err = getEnv("DB_PASSWORD")
	if err != nil {
		return nil, err
	}

	cfg.Name, err = getEnv("DB_NAME")
	if err != nil {
		return nil, err
	}

	cfg.SslMode, err = getEnv("DB_SSLMODE")
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func LoadRedisConfig() (*RedisConfig, error) {
	cfg := &RedisConfig{}

	var err error
	cfg.Addr, err = getEnv("REDIS_ADDR")
	if err != nil {
		return nil, err
	}
	cfg.Password, err = getEnv("REDIS_PASSWORD")
	if err != nil {
		return nil, err
	}

	cfg.RefreshPrefix, err = getEnv("REDIS_REFRESH_PREFIX")
	if err != nil {
		return nil, err
	}

	refreshExpirationString, err := getEnv("REDIS_REFRESH_EXPIRATION")
	if err != nil {
		return nil, err
	}

	refreshExpiration, err := time.ParseDuration(refreshExpirationString)
	if err != nil {
		return nil, err
	}

	cfg.RefreshExpiration = refreshExpiration

	redisDBString, err := getEnv("REDIS_DB")
	if err != nil {
		return nil, err
	}

	cfg.SessionDB, err = strconv.Atoi(redisDBString)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func LoadJWTConfig() (*JWTConfig, error) {
	cfg := &JWTConfig{}

	secretKeyString, err := getEnv("JWT_SECRET_KEY")
	if err != nil {
		return nil, err
	}

	cfg.SecretKey = []byte(secretKeyString)

	accessTokenTTLString, err := getEnv("JWT_ACCESS_TOKEN_TTL")
	if err != nil {
		return nil, err
	}

	accessTokenTTLDuration, err := time.ParseDuration(accessTokenTTLString)
	if err != nil {
		return nil, err
	}

	cfg.AccessTokenTTL = accessTokenTTLDuration

	refreshTokenBytesString, err := getEnv("JWT_REFRESH_TOKEN_BYTES")
	if err != nil {
		return nil, err
	}

	cfg.RefreshTokenBytes, err = strconv.Atoi(refreshTokenBytesString)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
