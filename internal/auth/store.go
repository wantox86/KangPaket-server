package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	IsAdmin      bool
	Disabled     bool
	CreatedAt    time.Time
}

type RefreshToken struct {
	ID        int64
	UserID    int64
	FamilyID  string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Store is the persistence boundary; MySQLStore is the real implementation.
type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string, isAdmin bool) (*User, error)
	UserByUsername(ctx context.Context, username string) (*User, error)
	UserByID(ctx context.Context, id int64) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	SetPassword(ctx context.Context, username, passwordHash string) error
	SetDisabled(ctx context.Context, username string, disabled bool) error
	DeleteUser(ctx context.Context, username string) error

	InsertRefresh(ctx context.Context, userID int64, tokenHash, familyID string, expiresAt time.Time, userAgent string) error
	RefreshByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// RevokeRefresh revokes one token; it reports whether this call did the revoking.
	RevokeRefresh(ctx context.Context, tokenHash string) (bool, error)
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeUserTokens(ctx context.Context, userID int64) error
	PurgeExpired(ctx context.Context, before time.Time) error
}
