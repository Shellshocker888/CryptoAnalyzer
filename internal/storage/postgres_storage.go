package storage

import (
	"context"
	"crypto_analyzer_auth_service/internal/domain"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	queryCreateUser = `
		INSERT INTO users (uuid, username, email, password_hash, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	queryGetUserByUsername = `
		SELECT uuid, username, email, password_hash, created_at
		FROM users
		WHERE username = $1
	`

	queryGetUserByEmail = `
		SELECT uuid, username, email, password_hash, created_at
		FROM users
		WHERE email = $1
	`

	queryGetUserByID = `
		SELECT username, email
		FROM users
		WHERE uuid = $1
	`

	queryCheckEmailExists = `
		SELECT 1 FROM users WHERE email = $1 LIMIT 1
	`
)

type UsersStorageInterface interface {
	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByUsernameEmail(ctx context.Context, username, email string) (*domain.User, error)
	GetUserByUserID(ctx context.Context, userID string) (*domain.User, error)
	EmailExists(ctx context.Context, email string) (bool, error)
	//UsernameExists(ctx context.Context, username string) (bool, error)
}

func (s *UserPostgresStorage) CreateUser(ctx context.Context, user *domain.User) error {
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	_, err := s.DB.ExecContext(ctx, queryCreateUser, user.ID, user.Username, user.Email, user.PasswordHash, user.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *UserPostgresStorage) GetUserByUsernameEmail(ctx context.Context, username, email string) (*domain.User, error) {
	var query string
	var value string

	if username != "" {
		query = queryGetUserByUsername
		value = username
	} else if email != "" {
		query = queryGetUserByEmail
		value = email
	} else {
		return nil, fmt.Errorf("username or email must be provided")
	}

	row := s.DB.QueryRowContext(ctx, query, value)

	var user domain.User
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (s *UserPostgresStorage) GetUserByUserID(ctx context.Context, userID string) (*domain.User, error) {

	if userID == "" {
		return nil, fmt.Errorf("userID is empty")
	}

	row := s.DB.QueryRowContext(ctx, queryGetUserByID, userID)

	var user domain.User
	err := row.Scan(
		&user.Username,
		&user.Email,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (s *UserPostgresStorage) EmailExists(ctx context.Context, email string) (bool, error) {
	row := s.DB.QueryRowContext(ctx, queryCheckEmailExists, email)

	var result int
	err := row.Scan(&result)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check user email: %w", err)
	}

	return true, nil
}

/*func (s *UserPostgresStorage) UsernameExists(ctx context.Context, username string) (bool, error) {
	query := `SELECT 1 FROM users WHERE username = $1 LIMIT 1`

	row := s.DB.QueryRowContext(ctx, query, username)

	var result int
	err := row.Scan(&result)
	if errors_my.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check user username: %w", err)
	}

	return true, nil
}*/
