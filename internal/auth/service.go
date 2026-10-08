package auth

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrWeakPassword       = errors.New("weak password")
	ErrUsernameTaken      = errors.New("username taken")
)

const (
	MinPasswordLen = 10
	maxPasswordLen = 256
)

var usernameRe = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

type Session struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	User         *User
}

type Service struct {
	Store      Store
	Hasher     *Hasher
	Secret     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Log        *slog.Logger
	Now        func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func NormalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func ValidateUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return ErrInvalidUsername
	}
	return nil
}

func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen || len(p) > maxPasswordLen {
		return ErrWeakPassword
	}
	return nil
}

func (s *Service) CreateUser(ctx context.Context, username, password string, admin bool) (*User, error) {
	username = NormalizeUsername(username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.CreateUser(ctx, username, hash, admin)
	if errors.Is(err, ErrExists) {
		return nil, ErrUsernameTaken
	}
	return u, err
}

func (s *Service) SetPassword(ctx context.Context, username, password string) error {
	username = NormalizeUsername(username)
	if err := ValidatePassword(password); err != nil {
		return err
	}
	u, err := s.Store.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		return err
	}
	if err := s.Store.SetPassword(ctx, username, hash); err != nil {
		return err
	}
	return s.Store.RevokeUserTokens(ctx, u.ID)
}

func (s *Service) SetDisabled(ctx context.Context, username string, disabled bool) error {
	username = NormalizeUsername(username)
	u, err := s.Store.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if err := s.Store.SetDisabled(ctx, username, disabled); err != nil {
		return err
	}
	if disabled {
		return s.Store.RevokeUserTokens(ctx, u.ID)
	}
	return nil
}

// Login always spends one hash verification, whether or not the user exists.
func (s *Service) Login(ctx context.Context, username, password, userAgent string) (*Session, error) {
	username = NormalizeUsername(username)
	if len(password) > maxPasswordLen || username == "" {
		return nil, ErrInvalidCredentials
	}
	u, err := s.Store.UserByUsername(ctx, username)
	if errors.Is(err, ErrNotFound) {
		s.Hasher.VerifyDummy(password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !s.Hasher.Verify(password, u.PasswordHash) || u.Disabled {
		return nil, ErrInvalidCredentials
	}
	family, err := newFamilyID()
	if err != nil {
		return nil, err
	}
	return s.issue(ctx, u, family, userAgent)
}

func (s *Service) issue(ctx context.Context, u *User, family, userAgent string) (*Session, error) {
	now := s.now()
	access, err := IssueAccessToken(s.Secret, u.ID, now, s.AccessTTL)
	if err != nil {
		return nil, err
	}
	refresh, hash, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	if err := s.Store.InsertRefresh(ctx, u.ID, hash, family, now.Add(s.RefreshTTL), userAgent); err != nil {
		return nil, err
	}
	return &Session{AccessToken: access, RefreshToken: refresh, ExpiresIn: int(s.AccessTTL.Seconds()), User: u}, nil
}

// Refresh rotates the token. Presenting an already-revoked token revokes its whole family.
func (s *Service) Refresh(ctx context.Context, token, userAgent string) (*Session, error) {
	hash := HashToken(token)
	rt, err := s.Store.RefreshByHash(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if rt.RevokedAt != nil {
		s.Log.Warn("refresh token reuse detected, revoking family", "user_id", rt.UserID)
		return nil, s.revokeFamilyErr(ctx, rt.FamilyID)
	}
	if !rt.ExpiresAt.After(s.now()) {
		return nil, ErrInvalidToken
	}
	won, err := s.Store.RevokeRefresh(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !won {
		s.Log.Warn("refresh token raced, revoking family", "user_id", rt.UserID)
		return nil, s.revokeFamilyErr(ctx, rt.FamilyID)
	}
	u, err := s.Store.UserByID(ctx, rt.UserID)
	if errors.Is(err, ErrNotFound) || (err == nil && u.Disabled) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	return s.issue(ctx, u, rt.FamilyID, userAgent)
}

func (s *Service) revokeFamilyErr(ctx context.Context, family string) error {
	if err := s.Store.RevokeFamily(ctx, family); err != nil {
		return err
	}
	return ErrInvalidToken
}

// Logout is idempotent: unknown or already-revoked tokens are not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	_, err := s.Store.RevokeRefresh(ctx, HashToken(token))
	return err
}

// Authenticate resolves an access token to an active user.
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	id, err := ParseAccessToken(s.Secret, token, s.now())
	if err != nil {
		return nil, ErrInvalidToken
	}
	u, err := s.Store.UserByID(ctx, id)
	if errors.Is(err, ErrNotFound) || (err == nil && u.Disabled) {
		return nil, ErrInvalidToken
	}
	return u, err
}
