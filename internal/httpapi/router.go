// Package httpapi wires the HTTP routes.
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/wantox86/KangPaket-server/internal/auth"
)

type Pinger interface {
	PingContext(ctx context.Context) error
}

type Options struct {
	DB                  Pinger
	Log                 *slog.Logger
	Auth                *auth.Service
	RegistrationEnabled bool
	TrustProxyHeaders   bool
	CORSAllowedOrigins  []string
	RateLimitPerMin     int
	RateLimitUserPerMin int
}

func NewRouter(o Options) http.Handler {
	db, log := o.DB, o.Log
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			log.Error("healthz: db ping failed", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if o.Auth != nil {
		newAuthHandler(o).routes(mux)
	}
	return securityHeaders(cors(o.CORSAllowedOrigins, logRequests(mux, log)))
}

var _ Pinger = (*sql.DB)(nil)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

func logRequests(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.code, "dur_ms", time.Since(start).Milliseconds())
	})
}
