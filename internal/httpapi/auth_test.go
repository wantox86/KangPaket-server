package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wantox86/KangPaket-server/internal/auth"
	"github.com/wantox86/KangPaket-server/internal/auth/authtest"
)

type env struct {
	h   http.Handler
	st  *authtest.MemStore
	svc *auth.Service
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hasher, err := auth.NewHasher(1024, 1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	st := authtest.NewMemStore()
	svc := &auth.Service{Store: st, Hasher: hasher, Secret: []byte(strings.Repeat("k", 40)),
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour, Log: log}
	if _, err := svc.CreateUser(context.Background(), "alice", "passw0rd-long", true); err != nil {
		t.Fatal(err)
	}
	o := Options{DB: fakeDB{}, Log: log, Auth: svc, RateLimitPerMin: 50, RateLimitUserPerMin: 50}
	if mod != nil {
		mod(&o)
	}
	return &env{h: NewRouter(o), st: st, svc: svc}
}

func (e *env) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:1234"
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not json: %q", rec.Body.String())
	}
	return m["error"]
}

func login(t *testing.T, e *env) map[string]any {
	t.Helper()
	rec := e.do("POST", "/auth/login", `{"username":"alice","password":"passw0rd-long"}`)
	if rec.Code != 200 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	var m map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m)
	return m
}

func TestLoginMeRefreshLogout(t *testing.T) {
	e := newEnv(t, nil)
	m := login(t, e)
	if m["expires_in"].(float64) != 900 || m["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("unexpected login body: %v", m)
	}
	access, refresh := m["access_token"].(string), m["refresh_token"].(string)

	rec := e.do("GET", "/auth/me", "", "Authorization", "Bearer "+access)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"is_admin":true`) {
		t.Fatalf("me: %d %s", rec.Code, rec.Body)
	}
	for _, h := range []string{"", "Bearer ", "Bearer junk", "Basic " + access} {
		if rec := e.do("GET", "/auth/me", "", "Authorization", h); rec.Code != 401 || errCode(t, rec) != "unauthorized" {
			t.Fatalf("header %q: %d", h, rec.Code)
		}
	}

	rec = e.do("POST", "/auth/refresh", `{"refresh_token":"`+refresh+`"}`)
	if rec.Code != 200 {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}
	var m2 map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m2)
	if rec := e.do("POST", "/auth/refresh", `{"refresh_token":"`+refresh+`"}`); rec.Code != 401 {
		t.Fatalf("reuse: %d", rec.Code)
	}
	if rec := e.do("POST", "/auth/refresh", `{"refresh_token":"`+m2["refresh_token"].(string)+`"}`); rec.Code != 401 {
		t.Fatalf("family should be revoked: %d", rec.Code)
	}
	if e.st.ActiveTokens() != 0 {
		t.Fatal("tokens left active")
	}

	m = login(t, e)
	for i := 0; i < 2; i++ {
		if rec := e.do("POST", "/auth/logout", `{"refresh_token":"`+m["refresh_token"].(string)+`"}`); rec.Code != 204 {
			t.Fatalf("logout #%d: %d", i, rec.Code)
		}
	}
	if rec := e.do("POST", "/auth/refresh", `{"refresh_token":"`+m["refresh_token"].(string)+`"}`); rec.Code != 401 {
		t.Fatalf("refresh after logout: %d", rec.Code)
	}
}

func TestNoUserEnumeration(t *testing.T) {
	e := newEnv(t, nil)
	a := e.do("POST", "/auth/login", `{"username":"alice","password":"wrong-password"}`)
	b := e.do("POST", "/auth/login", `{"username":"ghost","password":"wrong-password"}`)
	if a.Code != 401 || b.Code != 401 || a.Body.String() != b.Body.String() {
		t.Fatalf("responses differ: %d %q vs %d %q", a.Code, a.Body, b.Code, b.Body)
	}
	if errCode(t, a) != "invalid_credentials" {
		t.Fatal("unexpected code")
	}
}

func TestRegister(t *testing.T) {
	body := `{"username":"Newbie","password":"passw0rd-long"}`
	e := newEnv(t, nil)
	rec := e.do("POST", "/auth/register", body)
	if rec.Code != 403 || errCode(t, rec) != "registration_disabled" {
		t.Fatalf("disabled: %d %s", rec.Code, rec.Body)
	}

	e = newEnv(t, func(o *Options) { o.RegistrationEnabled = true })
	rec = e.do("POST", "/auth/register", body)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"username":"newbie"`) || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("enabled: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/auth/login", `{"username":"newbie","password":"passw0rd-long"}`); rec.Code != 200 {
		t.Fatalf("login after register: %d", rec.Code)
	}
	for body, want := range map[string]struct {
		code int
		err  string
	}{
		body: {409, "username_taken"},
		`{"username":"x","password":"passw0rd-long"}`: {400, "invalid_username"},
		`{"username":"okname","password":"short"}`:    {400, "invalid_password"},
		`not json`: {400, "invalid_request"},
	} {
		rec := e.do("POST", "/auth/register", body)
		if rec.Code != want.code || errCode(t, rec) != want.err {
			t.Fatalf("%s: got %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, nil)
	big := `{"username":"alice","password":"` + strings.Repeat("a", 2<<20) + `"}`
	rec := e.do("POST", "/auth/login", big)
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "payload_too_large" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RateLimitPerMin = 5; o.RateLimitUserPerMin = 100 })
	for i := 0; i < 5; i++ {
		if rec := e.do("POST", "/auth/login", `{"username":"alice","password":"nope-nope-nope"}`); rec.Code != 401 {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	rec := e.do("POST", "/auth/login", `{"username":"alice","password":"nope-nope-nope"}`)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || errCode(t, rec) != "rate_limited" {
		t.Fatalf("6th: %d %v", rec.Code, rec.Header())
	}
}

func TestPerUsernameRateLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RateLimitPerMin = 100; o.RateLimitUserPerMin = 2 })
	for i := 0; i < 2; i++ {
		e.do("POST", "/auth/login", `{"username":"alice","password":"nope-nope-nope"}`)
	}
	if rec := e.do("POST", "/auth/login", `{"username":"ALICE","password":"nope-nope-nope"}`); rec.Code != 429 {
		t.Fatalf("got %d", rec.Code)
	}
	if rec := e.do("POST", "/auth/login", `{"username":"other","password":"nope-nope-nope"}`); rec.Code != 401 {
		t.Fatalf("other user should not be limited: %d", rec.Code)
	}
}

func TestProxyHeaderTrust(t *testing.T) {
	for _, trust := range []bool{false, true} {
		e := newEnv(t, func(o *Options) { o.RateLimitPerMin = 1; o.RateLimitUserPerMin = 100; o.TrustProxyHeaders = trust })
		e.do("POST", "/auth/login", `{"username":"alice","password":"nope-nope-nope"}`, "CF-Connecting-IP", "1.1.1.1")
		rec := e.do("POST", "/auth/login", `{"username":"alice","password":"nope-nope-nope"}`, "CF-Connecting-IP", "2.2.2.2")
		// Untrusted: header ignored, both calls share the socket IP -> limited.
		// Trusted: distinct client IPs -> not limited.
		if limited := rec.Code == 429; limited == trust {
			t.Fatalf("trust=%v got %d", trust, rec.Code)
		}
	}
}

func TestRequireAuthInjectsUser(t *testing.T) {
	e := newEnv(t, nil)
	m := login(t, e)
	var got int64
	h := RequireAuth(e.svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = UserID(r.Context()) }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "bearer "+m["access_token"].(string))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || got != 1 {
		t.Fatalf("code=%d id=%d", rec.Code, got)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 401 {
		t.Fatalf("no header: %d", rec.Code)
	}
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do("GET", "/healthz", "", "Origin", "https://evil.example")
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("headers: %v", rec.Header())
	}
	e = newEnv(t, func(o *Options) { o.CORSAllowedOrigins = []string{"https://ok.example"} })
	if rec := e.do("GET", "/healthz", "", "Origin", "https://ok.example"); rec.Header().Get("Access-Control-Allow-Origin") != "https://ok.example" {
		t.Fatal("allowed origin missing")
	}
	if rec := e.do("GET", "/healthz", "", "Origin", "https://evil.example"); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin echoed")
	}
}

func TestLockoutScopedToAttackerIP(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RateLimitPerMin = 100; o.RateLimitUserPerMin = 2; o.TrustProxyHeaders = true })
	bad := `{"username":"alice","password":"nope-nope-nope"}`
	for i := 0; i < 2; i++ {
		e.do("POST", "/auth/login", bad, "CF-Connecting-IP", "6.6.6.6")
	}
	if rec := e.do("POST", "/auth/login", bad, "CF-Connecting-IP", "6.6.6.6"); rec.Code != 429 {
		t.Fatalf("attacker should be limited: %d", rec.Code)
	}
	// The real user, from another IP, is not locked out by the attacker.
	good := `{"username":"alice","password":"passw0rd-long"}`
	if rec := e.do("POST", "/auth/login", good, "CF-Connecting-IP", "7.7.7.7"); rec.Code != 200 {
		t.Fatalf("victim locked out: %d", rec.Code)
	}
}

func TestDistributedGuessingHitsGlobalUsernameCeiling(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RateLimitPerMin = 1000; o.RateLimitUserPerMin = 1; o.TrustProxyHeaders = true })
	bad := `{"username":"alice","password":"nope-nope-nope"}`
	var last int
	for i := 0; i < globalUserLimitFactor+1; i++ {
		last = e.do("POST", "/auth/login", bad, "CF-Connecting-IP", "9.9.9."+strconv.Itoa(i+1)).Code
	}
	if last != 429 {
		t.Fatalf("expected global per-username ceiling, got %d", last)
	}
}

func TestClientIPNormalisation(t *testing.T) {
	h := &authHandler{trustProxy: true}
	for in, want := range map[string]string{
		"1.2.3.4":          "1.2.3.4",
		" 1.2.3.4 ":        "1.2.3.4",
		"::ffff:1.2.3.4":   "1.2.3.4",
		"fe80::1%eth0":     "fe80::1",
		"not-an-ip":        "10.0.0.1",
		"1.2.3.4, 5.6.7.8": "10.0.0.1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.1:99"
		r.Header.Set("CF-Connecting-IP", in)
		if got := h.clientIP(r); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestLimiterKeyBoundsLongUsernames(t *testing.T) {
	if k := limiterKey(strings.Repeat("a", 100000)); len(k) > 80 {
		t.Fatalf("key too long: %d", len(k))
	}
	if limiterKey("alice") != "alice" {
		t.Fatal("short keys unchanged")
	}
}
