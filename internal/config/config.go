package config

import (
	"crypto_analyzer_auth_service/internal/config/model"
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"strconv"
	"time"
)

func getEnv(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("failed to load env %s", key)
	}

	return val, nil
}

func LoadConfig() (*model.Config, error) {
	env := ".env"

	if os.Getenv("APP_ENV") == "test" {
		env = ".env.test"
	}

	err := godotenv.Load(env)
	if err != nil {
		return nil, fmt.Errorf("failed to load env: %w", err)
	}

	cfgPostgres := &model.PostgresConfig{}

	cfgPostgres.Host, err = getEnv("DB_HOST")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgPostgres.Port, err = getEnv("DB_PORT")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgPostgres.User, err = getEnv("DB_USER")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgPostgres.Password, err = getEnv("DB_PASSWORD")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgPostgres.Name, err = getEnv("DB_NAME")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgPostgres.SslMode, err = getEnv("DB_SSLMODE")
	if err != nil {
		return nil, fmt.Errorf("failed to load postgres config: %w", err)
	}

	cfgRedis := &model.RedisConfig{}

	cfgRedis.Addr, err = getEnv("REDIS_ADDR")
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}
	cfgRedis.Password, err = getEnv("REDIS_PASSWORD")
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	cfgRedis.RefreshPrefix, err = getEnv("REDIS_REFRESH_PREFIX")
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	var refreshExpirationString string
	refreshExpirationString, err = getEnv("REDIS_REFRESH_EXPIRATION")
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	var refreshExpiration time.Duration
	refreshExpiration, err = time.ParseDuration(refreshExpirationString)
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	cfgRedis.RefreshExpiration = refreshExpiration

	var redisDBString string
	redisDBString, err = getEnv("REDIS_DB")
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	cfgRedis.SessionDB, err = strconv.Atoi(redisDBString)
	if err != nil {
		return nil, fmt.Errorf("failed to load redis config: %w", err)
	}

	cfgJwt := &model.JwtConfig{}

	secretKeyString, err := getEnv("JWT_SECRET_KEY")
	if err != nil {
		return nil, fmt.Errorf("failed to load jwt config: %w", err)
	}

	cfgJwt.SecretKey = []byte(secretKeyString)

	var accessTokenTtlString string
	accessTokenTtlString, err = getEnv("JWT_ACCESS_TOKEN_TTL")
	if err != nil {
		return nil, fmt.Errorf("failed to load jwt config: %w", err)
	}

	var accessTokenTtlDuration time.Duration
	accessTokenTtlDuration, err = time.ParseDuration(accessTokenTtlString)
	if err != nil {
		return nil, fmt.Errorf("failed to load jwt config: %w", err)
	}

	cfgJwt.AccessTokenTTL = accessTokenTtlDuration

	var refreshTokenBytesString string
	refreshTokenBytesString, err = getEnv("JWT_REFRESH_TOKEN_BYTES")
	if err != nil {
		return nil, fmt.Errorf("failed to load jwt config: %w", err)
	}

	cfgJwt.RefreshTokenBytes, err = strconv.Atoi(refreshTokenBytesString)
	if err != nil {
		return nil, fmt.Errorf("failed to load jwt config: %w", err)
	}

	return &model.Config{
		PostgresCfg: cfgPostgres,
		RedisCfg:    cfgRedis,
		JwtCfg:      cfgJwt,
	}, nil
}
