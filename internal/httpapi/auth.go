package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/wantox86/KangPaket-server/internal/auth"
)

const maxBodyBytes = 1 << 20

// globalUserLimitFactor sizes the per-username limiter that counts attempts from
// every IP. Locking someone out therefore needs this many times the per-IP
// budget, which a single client cannot reach (its own IP limiter trips first).
const globalUserLimitFactor = 10

type authHandler struct {
	svc          *auth.Service
	log          *slog.Logger
	registration bool
	trustProxy   bool
	ipLogin      *auth.Limiter // per client IP
	userLogin    *auth.Limiter // per IP+username: lockout is scoped to the attacker's IP
	nameLogin    *auth.Limiter // per username across all IPs: high ceiling vs distributed guessing
	ipRefresh    *auth.Limiter
	ipRegister   *auth.Limiter
}

func newAuthHandler(o Options) *authHandler {
	mk := func(n int) *auth.Limiter { return auth.NewLimiter(n, time.Minute) }
	h := &authHandler{
		svc: o.Auth, log: o.Log, registration: o.RegistrationEnabled, trustProxy: o.TrustProxyHeaders,
		ipLogin: mk(o.RateLimitPerMin), userLogin: mk(o.RateLimitUserPerMin),
		nameLogin: mk(o.RateLimitUserPerMin * globalUserLimitFactor),
		ipRefresh: mk(o.RateLimitPerMin), ipRegister: mk(o.RateLimitPerMin),
	}
	go func() {
		for range time.Tick(time.Minute) {
			h.ipLogin.Cleanup()
			h.userLogin.Cleanup()
			h.nameLogin.Cleanup()
			h.ipRefresh.Cleanup()
			h.ipRegister.Cleanup()
		}
	}()
	return h
}

func (h *authHandler) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", h.login)
	mux.HandleFunc("POST /auth/refresh", h.refresh)
	mux.HandleFunc("POST /auth/logout", h.logout)
	mux.HandleFunc("POST /auth/register", h.register)
	mux.Handle("GET /auth/me", RequireAuth(h.svc, http.HandlerFunc(h.me)))
}

type userJSON struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
}

func toUserJSON(u *auth.User) userJSON { return userJSON{u.ID, u.Username, u.IsAdmin} }

type sessionJSON struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"`
	User         userJSON `json:"user"`
}

func (h *authHandler) clientIP(r *http.Request) string {
	if h.trustProxy {
		// Only a literal IP is accepted; zones and IPv4-mapped forms are normalised
		// so one client cannot mint many limiter keys.
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
			return a.WithZone("").Unmap().String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *authHandler) limit(w http.ResponseWriter, l *auth.Limiter, key string) bool {
	ok, retry := l.Allow(key)
	if !ok {
		secs := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, "rate_limited")
	}
	return ok
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	return true
}

// limiterKey bounds limiter map keys: usernames can be up to the 1 MiB body size.
func limiterKey(name string) string {
	if len(name) > 64 {
		sum := sha256.Sum256([]byte(name))
		return "h:" + hex.EncodeToString(sum[:])
	}
	return name
}

// shortHash lets logs correlate attempts without recording the username.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if !h.limit(w, h.ipLogin, ip) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	name := auth.NormalizeUsername(req.Username)
	key := limiterKey(name)
	if !h.limit(w, h.userLogin, ip+"|"+key) || !h.limit(w, h.nameLogin, key) {
		return
	}
	s, err := h.svc.Login(r.Context(), name, req.Password, r.UserAgent())
	if errors.Is(err, auth.ErrInvalidCredentials) {
		h.log.Warn("login failed", "user_hash", shortHash(name), "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err != nil {
		h.log.Error("login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	h.log.Info("login ok", "user_id", s.User.ID, "ip", ip)
	writeSession(w, s)
}

func writeSession(w http.ResponseWriter, s *auth.Session) {
	writeJSON(w, http.StatusOK, sessionJSON{s.AccessToken, s.RefreshToken, s.ExpiresIn, toUserJSON(s.User)})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if !h.limit(w, h.ipRefresh, ip) {
		return
	}
	var req refreshReq
	if !decode(w, r, &req) {
		return
	}
	s, err := h.svc.Refresh(r.Context(), req.RefreshToken, r.UserAgent())
	if errors.Is(err, auth.ErrInvalidToken) {
		h.log.Warn("refresh rejected", "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err != nil {
		h.log.Error("refresh", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeSession(w, s)
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if !decode(w, r, &req) {
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		h.log.Error("logout", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toUserJSON(UserFromContext(r.Context())))
}

func (h *authHandler) register(w http.ResponseWriter, r *http.Request) {
	if !h.registration {
		writeError(w, http.StatusForbidden, "registration_disabled")
		return
	}
	if !h.limit(w, h.ipRegister, h.clientIP(r)) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := h.svc.CreateUser(r.Context(), req.Username, req.Password, false)
	switch {
	case errors.Is(err, auth.ErrInvalidUsername):
		writeError(w, http.StatusBadRequest, "invalid_username")
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "invalid_password")
	case errors.Is(err, auth.ErrUsernameTaken):
		writeError(w, http.StatusConflict, "username_taken")
	case err != nil:
		h.log.Error("register", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
	default:
		writeJSON(w, http.StatusCreated, toUserJSON(u))
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
