package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/wantox86/KangPaket-server/internal/auth"
	"github.com/wantox86/KangPaket-server/internal/auth/authtest"
)

var secret = []byte(strings.Repeat("s", 40))

// Cheap parameters keep tests fast; production params are in DefaultHasher.
func testHasher(t testing.TB) *auth.Hasher {
	h, err := auth.NewHasher(1024, 1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashVerify(t *testing.T) {
	h := testHasher(t)
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected format: %q", enc)
	}
	if !h.Verify("correct horse battery", enc) {
		t.Fatal("correct password rejected")
	}
	if h.Verify("wrong", enc) {
		t.Fatal("wrong password accepted")
	}
	enc2, _ := h.Hash("correct horse battery")
	if enc == enc2 {
		t.Fatal("salt must be random per hash")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=1,t=1$x$y", "$bcrypt$v=19$m=1024,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=19$m=999999999,t=1,p=1$AAAA$AAAA", "$argon2id$v=19$m=1024,t=1,p=1$!!$AAAA"} {
		if h.Verify("x", bad) {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestJWT(t *testing.T) {
	now := time.Now()
	tok, err := auth.IssueAccessToken(secret, 42, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := auth.ParseAccessToken(secret, tok, now); err != nil || id != 42 {
		t.Fatalf("valid token: id=%d err=%v", id, err)
	}
	if _, err := auth.ParseAccessToken(secret, tok, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := auth.ParseAccessToken([]byte(strings.Repeat("o", 40)), tok, now); err == nil {
		t.Fatal("wrong signature accepted")
	}

	claims := jwt.RegisteredClaims{Subject: "42", Issuer: "kangpaket-server", ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := auth.ParseAccessToken(secret, none, now); err == nil {
		t.Fatal("alg none accepted")
	}
	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(secret)
	if _, err := auth.ParseAccessToken(secret, hs512, now); err == nil {
		t.Fatal("HS512 accepted")
	}
	claims.Issuer = "other"
	wrongIss, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if _, err := auth.ParseAccessToken(secret, wrongIss, now); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	noExp, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "1", Issuer: "kangpaket-server"}).SignedString(secret)
	if _, err := auth.ParseAccessToken(secret, noExp, now); err == nil {
		t.Fatal("token without exp accepted")
	}
	if _, err := auth.ParseAccessToken(secret, "garbage", now); err == nil {
		t.Fatal("garbage accepted")
	}
}

func newSvc(t *testing.T) (*auth.Service, *authtest.MemStore, *time.Time) {
	st := authtest.NewMemStore()
	clock := time.Now()
	svc := &auth.Service{
		Store: st, Hasher: testHasher(t), Secret: secret,
		AccessTTL: 15 * time.Minute, RefreshTTL: 30 * 24 * time.Hour,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return clock },
	}
	return svc, st, &clock
}

func TestLoginAndRotation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newSvc(t)
	if _, err := svc.CreateUser(ctx, "Alice", "passw0rd-long", false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "alice", "bad", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := svc.Login(ctx, "nobody", "passw0rd-long", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown user must give the same error: %v", err)
	}
	s1, err := svc.Login(ctx, "ALICE", "passw0rd-long", "ua")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := svc.Refresh(ctx, s1.RefreshToken, "ua")
	if err != nil {
		t.Fatal(err)
	}
	if s2.RefreshToken == s1.RefreshToken {
		t.Fatal("refresh token not rotated")
	}
	s3, err := svc.Refresh(ctx, s2.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	// Reusing the first (revoked) token kills the whole family, including s3.
	if _, err := svc.Refresh(ctx, s1.RefreshToken, ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := svc.Refresh(ctx, s3.RefreshToken, ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("family should be revoked: %v", err)
	}
	if n := st.ActiveTokens(); n != 0 {
		t.Fatalf("active tokens = %d", n)
	}
	if _, err := svc.Refresh(ctx, "unknown", ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestOtherFamilySurvivesReuse(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newSvc(t)
	svc.CreateUser(ctx, "bob", "passw0rd-long", false)
	a, _ := svc.Login(ctx, "bob", "passw0rd-long", "")
	b, _ := svc.Login(ctx, "bob", "passw0rd-long", "")
	a2, _ := svc.Refresh(ctx, a.RefreshToken, "")
	svc.Refresh(ctx, a.RefreshToken, "") // reuse kills family A only
	if _, err := svc.Refresh(ctx, a2.RefreshToken, ""); err == nil {
		t.Fatal("family A should be dead")
	}
	if _, err := svc.Refresh(ctx, b.RefreshToken, ""); err != nil {
		t.Fatalf("family B should survive: %v", err)
	}
}

func TestRefreshExpiryLogoutDisable(t *testing.T) {
	ctx := context.Background()
	svc, _, clock := newSvc(t)
	svc.CreateUser(ctx, "carol", "passw0rd-long", false)
	s, _ := svc.Login(ctx, "carol", "passw0rd-long", "")

	if err := svc.Logout(ctx, s.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(ctx, s.RefreshToken); err != nil {
		t.Fatalf("logout must be idempotent: %v", err)
	}
	if err := svc.Logout(ctx, "never-existed"); err != nil {
		t.Fatalf("logout unknown: %v", err)
	}
	if _, err := svc.Refresh(ctx, s.RefreshToken, ""); err == nil {
		t.Fatal("logged-out token refreshed")
	}

	s, _ = svc.Login(ctx, "carol", "passw0rd-long", "")
	*clock = clock.Add(31 * 24 * time.Hour)
	if _, err := svc.Refresh(ctx, s.RefreshToken, ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired refresh: %v", err)
	}
	*clock = clock.Add(-31 * 24 * time.Hour)

	s, _ = svc.Login(ctx, "carol", "passw0rd-long", "")
	if err := svc.SetDisabled(ctx, "carol", true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "carol", "passw0rd-long", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
	if _, err := svc.Refresh(ctx, s.RefreshToken, ""); err == nil {
		t.Fatal("disabled user refreshed")
	}
	if _, err := svc.Authenticate(ctx, s.AccessToken); err == nil {
		t.Fatal("disabled user authenticated")
	}
	svc.SetDisabled(ctx, "carol", false)
	if _, err := svc.Authenticate(ctx, s.AccessToken); err != nil {
		t.Fatalf("re-enabled user: %v", err)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newSvc(t)
	for _, u := range []string{"ab", strings.Repeat("a", 33), "sp ace", "ünï", "a/b"} {
		if _, err := svc.CreateUser(ctx, u, "passw0rd-long", false); !errors.Is(err, auth.ErrInvalidUsername) {
			t.Fatalf("username %q: %v", u, err)
		}
	}
	if _, err := svc.CreateUser(ctx, "dave", "short", false); !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("short password: %v", err)
	}
	if _, err := svc.CreateUser(ctx, "dave", "passw0rd-long", false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(ctx, "DAVE", "passw0rd-long", false); !errors.Is(err, auth.ErrUsernameTaken) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	l := auth.NewLimiter(3, time.Minute)
	now := time.Now()
	l.SetClock(func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("attempt %d denied", i)
		}
	}
	ok, retry := l.Allow("k")
	if ok || retry <= 0 || retry > time.Minute {
		t.Fatalf("expected denial with retry, got ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("other"); !ok {
		t.Fatal("keys must be independent")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("window should have reset")
	}
	now = now.Add(2 * time.Minute)
	l.Cleanup()
	if l.Len() != 0 {
		t.Fatalf("cleanup left %d keys", l.Len())
	}
}
