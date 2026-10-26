package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wantox86/KangPaket-server/internal/auth"
	"github.com/wantox86/KangPaket-server/internal/syncstore"
)

const (
	maxPushBodyBytes   = 5 << 20
	maxPushItems       = 500
	maxPayloadBytes    = 256 << 10
	maxLabelRunes      = 255
	defaultPullLimit   = 500
	maxPullLimit       = 1000
	pullPayloadBudget  = 4 << 20 // keeps a pull response small enough for the 128m container
	syncRatePerMin     = 120
	maxClientUpdatedAt = int64(32503680000000) // year 3000, in ms
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type syncHandler struct {
	svc     *auth.Service
	store   syncstore.Store
	log     *slog.Logger
	limiter *auth.Limiter
}

func newSyncHandler(o Options) *syncHandler {
	h := &syncHandler{svc: o.Auth, store: o.Sync, log: o.Log, limiter: auth.NewLimiter(syncRatePerMin, time.Minute)}
	go func() {
		for range time.Tick(time.Minute) {
			h.limiter.Cleanup()
		}
	}()
	return h
}

func (h *syncHandler) routes(mux *http.ServeMux) {
	mux.Handle("GET /sync/pull", RequireAuth(h.svc, http.HandlerFunc(h.pull)))
	mux.Handle("POST /sync/push", RequireAuth(h.svc, http.HandlerFunc(h.push)))
}

func (h *syncHandler) allow(w http.ResponseWriter, r *http.Request) bool {
	ok, retry := h.limiter.Allow(strconv.FormatInt(UserID(r.Context()), 10))
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited")
	}
	return ok
}

func (h *syncHandler) pull(w http.ResponseWriter, r *http.Request) {
	if !h.allow(w, r) {
		return
	}
	q := r.URL.Query()
	since, limit := int64(0), defaultPullLimit
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_since")
			return
		}
		since = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPullLimit {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = n
	}
	res, err := h.store.Pull(r.Context(), UserID(r.Context()), since, limit, pullPayloadBudget)
	if err != nil {
		h.log.Error("sync pull", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type pushItem struct {
	ID              string          `json:"id"`
	Collection      string          `json:"collection"` // profiles
	Name            string          `json:"name"`       // environments
	ClientUpdatedAt int64           `json:"client_updated_at"`
	Deleted         bool            `json:"deleted"`
	Payload         json.RawMessage `json:"payload"`
}

type pushReq struct {
	Profiles     []pushItem `json:"profiles"`
	Environments []pushItem `json:"environments"`
}

func (h *syncHandler) push(w http.ResponseWriter, r *http.Request) {
	if !h.allow(w, r) {
		return
	}
	var req pushReq
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	if len(req.Profiles)+len(req.Environments) > maxPushItems {
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_items")
		return
	}
	items := make([]syncstore.Item, 0, len(req.Profiles)+len(req.Environments))
	seen := map[string]bool{}
	for _, set := range []struct {
		kind  string
		items []pushItem
	}{{syncstore.KindProfile, req.Profiles}, {syncstore.KindEnvironment, req.Environments}} {
		for _, p := range set.items {
			it, code, msg := toItem(set.kind, p)
			if msg != "" {
				writeError(w, code, msg)
				return
			}
			k := it.Kind + "/" + it.ID
			if seen[k] {
				writeError(w, http.StatusBadRequest, "duplicate_id")
				return
			}
			seen[k] = true
			items = append(items, it)
		}
	}
	res, err := h.store.Push(r.Context(), UserID(r.Context()), items)
	if err != nil {
		h.log.Error("sync push", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func toItem(kind string, p pushItem) (syncstore.Item, int, string) {
	if !uuidRe.MatchString(p.ID) {
		return syncstore.Item{}, http.StatusBadRequest, "invalid_id"
	}
	if p.ClientUpdatedAt <= 0 || p.ClientUpdatedAt > maxClientUpdatedAt {
		return syncstore.Item{}, http.StatusBadRequest, "invalid_client_updated_at"
	}
	label := p.Collection
	if kind == syncstore.KindEnvironment {
		label = p.Name
	}
	if utf8.RuneCountInString(label) > maxLabelRunes || !utf8.ValidString(label) {
		return syncstore.Item{}, http.StatusBadRequest, "invalid_label"
	}
	it := syncstore.Item{Kind: kind, ID: strings.ToLower(p.ID), Label: label, ClientUpdatedAt: p.ClientUpdatedAt, Deleted: p.Deleted}
	if p.Deleted {
		it.Label = ""
		return it, 0, ""
	}
	if len(p.Payload) > maxPayloadBytes {
		return syncstore.Item{}, http.StatusRequestEntityTooLarge, "item_too_large"
	}
	var buf bytes.Buffer
	if len(p.Payload) == 0 || json.Compact(&buf, p.Payload) != nil || buf.Bytes()[0] != '{' {
		return syncstore.Item{}, http.StatusBadRequest, "invalid_payload"
	}
	it.Payload = buf.Bytes()
	return it, 0, ""
}
