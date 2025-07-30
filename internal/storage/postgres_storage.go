package storage

import (
	"context"
	"crypto_analyzer_auth_service/internal/domain"
	"crypto_analyzer_auth_service/internal/interfaces"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var _ interfaces.UsersStorage = (*UserPostgresStorage)(nil)

type UserPostgresStorage struct {
	DB *sql.DB
}

func NewUserStorage(db *sql.DB) (*UserPostgresStorage, error) {
	query := `CREATE TABLE IF NOT EXISTS users (
              id serial primary key,
              uuid TEXT NOT NULL UNIQUE,
              username VARCHAR(50) NOT NULL UNIQUE,
              email VARCHAR(255) NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
    		  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`

	_, err := db.Exec(query)
	if err != nil {
		return nil, fmt.Errorf("error creating new user storage: %w", err)
	}

	return &UserPostgresStorage{DB: db}, nil
}

func (s *UserPostgresStorage) CreateUser(ctx context.Context, user *domain.User) error {
	query := `INSERT INTO users (uuid, username, email, password_hash, created_at)
VALUES ($1, $2, $3, $4, $5)`

	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	_, err := s.DB.ExecContext(ctx, query, user.ID, user.Username, user.Email, user.PasswordHash, user.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *UserPostgresStorage) GetUserByUsernameEmail(ctx context.Context, username, email string) (*domain.User, error) {
	var field, target string

	if username != "" {
		field = "username"
		target = username
	} else if email != "" {
		field = "email"
		target = email
	}

	query := fmt.Sprintf("SELECT uuid, username, email, password_hash, created_at FROM users WHERE %s = $1", field)

	row := s.DB.QueryRowContext(ctx, query, target)

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
		return nil, errors.New("userID is empty")
	}

	query := `SELECT username, email FROM users WHERE uuid = $1`

	row := s.DB.QueryRowContext(ctx, query, userID)

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
	query := `SELECT 1 FROM users WHERE email = $1 LIMIT 1`

	row := s.DB.QueryRowContext(ctx, query, email)

	var result int
	err := row.Scan(&result)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check user mail: %w", err)
	}

	return true, nil
}

func (s *UserPostgresStorage) UsernameExists(ctx context.Context, username string) (bool, error) {
	query := `SELECT 1 FROM users WHERE username = $1 LIMIT 1`

	row := s.DB.QueryRowContext(ctx, query, username)

	var result int
	err := row.Scan(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check user username: %w", err)
	}

	return true, nil
}

/*CreateUser(ctx context.Context, user *domain.User) error
GetUserByEmail(email string) (domain.User, error)
EmailExists(email string) (bool, error)
UsernameExists(username string) (bool, error)*/
