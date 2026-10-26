// Package authtest provides an in-memory auth.Store for tests.
package authtest

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wantox86/KangPaket-server/internal/auth"
)

type tok struct {
	auth.RefreshToken
	hash string
}

type MemStore struct {
	mu     sync.Mutex
	nextID int64
	users  map[int64]*auth.User
	tokens map[string]*tok
}

func NewMemStore() *MemStore {
	return &MemStore{users: map[int64]*auth.User{}, tokens: map[string]*tok{}}
}

func (m *MemStore) find(name string) *auth.User {
	for _, u := range m.users {
		if strings.EqualFold(u.Username, name) {
			return u
		}
	}
	return nil
}

func (m *MemStore) CreateUser(_ context.Context, name, hash string, admin bool) (*auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.find(name) != nil {
		return nil, auth.ErrExists
	}
	m.nextID++
	u := &auth.User{ID: m.nextID, Username: name, PasswordHash: hash, IsAdmin: admin, CreatedAt: time.Now()}
	m.users[u.ID] = u
	c := *u
	return &c, nil
}

func (m *MemStore) UserByUsername(_ context.Context, name string) (*auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.find(name)
	if u == nil {
		return nil, auth.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *MemStore) UserByID(_ context.Context, id int64) (*auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u == nil {
		return nil, auth.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *MemStore) ListUsers(context.Context) ([]auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []auth.User
	for _, u := range m.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) mutate(name string, f func(*auth.User)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.find(name)
	if u == nil {
		return auth.ErrNotFound
	}
	f(u)
	return nil
}

func (m *MemStore) SetPassword(_ context.Context, name, hash string) error {
	return m.mutate(name, func(u *auth.User) { u.PasswordHash = hash })
}

func (m *MemStore) SetDisabled(_ context.Context, name string, d bool) error {
	return m.mutate(name, func(u *auth.User) { u.Disabled = d })
}

func (m *MemStore) DeleteUser(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.find(name)
	if u == nil {
		return auth.ErrNotFound
	}
	delete(m.users, u.ID)
	for h, t := range m.tokens {
		if t.UserID == u.ID {
			delete(m.tokens, h)
		}
	}
	return nil
}

func (m *MemStore) InsertRefresh(_ context.Context, uid int64, hash, family string, exp time.Time, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[hash] = &tok{RefreshToken: auth.RefreshToken{ID: int64(len(m.tokens) + 1), UserID: uid, FamilyID: family, ExpiresAt: exp}, hash: hash}
	return nil
}

func (m *MemStore) RefreshByHash(_ context.Context, hash string) (*auth.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tokens[hash]
	if t == nil {
		return nil, auth.ErrNotFound
	}
	c := t.RefreshToken
	return &c, nil
}

func (m *MemStore) RevokeRefresh(_ context.Context, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tokens[hash]
	if t == nil || t.RevokedAt != nil {
		return false, nil
	}
	now := time.Now()
	t.RevokedAt = &now
	return true, nil
}

func (m *MemStore) revokeWhere(f func(*tok) bool) {
	now := time.Now()
	for _, t := range m.tokens {
		if t.RevokedAt == nil && f(t) {
			t.RevokedAt = &now
		}
	}
}

func (m *MemStore) RevokeFamily(_ context.Context, family string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeWhere(func(t *tok) bool { return t.FamilyID == family })
	return nil
}

func (m *MemStore) RevokeUserTokens(_ context.Context, uid int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeWhere(func(t *tok) bool { return t.UserID == uid })
	return nil
}

func (m *MemStore) PurgeExpired(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, t := range m.tokens {
		if t.ExpiresAt.Before(before) {
			delete(m.tokens, h)
		}
	}
	return nil
}

// ActiveTokens counts unrevoked tokens, for assertions.
func (m *MemStore) ActiveTokens() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tokens {
		if t.RevokedAt == nil {
			n++
		}
	}
	return n
}
