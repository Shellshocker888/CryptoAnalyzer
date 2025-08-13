package model

import "time"

type Config struct {
	PostgresCfg *PostgresConfig
	RedisCfg    *RedisConfig
	JwtCfg      *JwtConfig
}

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

type JwtConfig struct {
	SecretKey         []byte
	AccessTokenTTL    time.Duration
	RefreshTokenBytes int
}
