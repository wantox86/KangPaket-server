package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

type MySQLStore struct{ db *sql.DB }

func NewMySQLStore(db *sql.DB) *MySQLStore { return &MySQLStore{db: db} }

const userCols = "id, username, password_hash, is_admin, disabled, created_at"

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.Disabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *MySQLStore) CreateUser(ctx context.Context, username, hash string, isAdmin bool) (*User, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", username, hash, isAdmin)
	var me *mysql.MySQLError
	if errors.As(err, &me) && me.Number == 1062 {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

func (s *MySQLStore) UserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username = ?", username))
}

func (s *MySQLStore) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id))
}

func (s *MySQLStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *MySQLStore) exec1(ctx context.Context, q string, args ...any) error {
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func (s *MySQLStore) requireUser(ctx context.Context, username string) error {
	_, err := s.UserByUsername(ctx, username)
	return err
}

func (s *MySQLStore) SetPassword(ctx context.Context, username, hash string) error {
	if err := s.requireUser(ctx, username); err != nil {
		return err
	}
	return s.exec1(ctx, "UPDATE users SET password_hash = ? WHERE username = ?", hash, username)
}

func (s *MySQLStore) SetDisabled(ctx context.Context, username string, disabled bool) error {
	if err := s.requireUser(ctx, username); err != nil {
		return err
	}
	return s.exec1(ctx, "UPDATE users SET disabled = ? WHERE username = ?", disabled, username)
}

func (s *MySQLStore) DeleteUser(ctx context.Context, username string) error {
	if err := s.requireUser(ctx, username); err != nil {
		return err
	}
	return s.exec1(ctx, "DELETE FROM users WHERE username = ?", username)
}

func (s *MySQLStore) InsertRefresh(ctx context.Context, userID int64, tokenHash, familyID string, expiresAt time.Time, ua string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, user_agent) VALUES (?, ?, ?, ?, ?)",
		userID, tokenHash, familyID, expiresAt.UTC(), sql.NullString{String: ua, Valid: ua != ""})
	return err
}

func (s *MySQLStore) RefreshByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var t RefreshToken
	var revoked sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?", tokenHash).
		Scan(&t.ID, &t.UserID, &t.FamilyID, &t.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		t.RevokedAt = &revoked.Time
	}
	return &t, nil
}

func (s *MySQLStore) RevokeRefresh(ctx context.Context, tokenHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP(3) WHERE token_hash = ? AND revoked_at IS NULL", tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *MySQLStore) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP(3) WHERE family_id = ? AND revoked_at IS NULL", familyID)
	return err
}

func (s *MySQLStore) RevokeUserTokens(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ? AND revoked_at IS NULL", userID)
	return err
}

func (s *MySQLStore) PurgeExpired(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE expires_at < ?", before.UTC())
	return err
}
