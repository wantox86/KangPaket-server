package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeDB struct{ err error }

func (f fakeDB) PingContext(context.Context) error { return f.err }

func TestHealthz(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		err  error
		code int
	}{{nil, 200}, {errors.New("down"), http.StatusServiceUnavailable}} {
		rec := httptest.NewRecorder()
		NewRouter(fakeDB{tc.err}, log).ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		if rec.Code != tc.code {
			t.Fatalf("got %d want %d", rec.Code, tc.code)
		}
	}
}
