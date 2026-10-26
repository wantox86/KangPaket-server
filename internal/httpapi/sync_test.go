package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/wantox86/KangPaket-server/internal/syncstore"
	"github.com/wantox86/KangPaket-server/internal/syncstore/synctest"
)

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
	idE = "33333333-3333-4333-8333-333333333333"
)

type syncEnv struct {
	*env
	alice, bob string // auth header values
}

func newSyncEnv(t *testing.T) *syncEnv {
	t.Helper()
	e := newEnv(t, func(o *Options) { o.Sync = synctest.NewMemStore() })
	if _, err := e.svc.CreateUser(context.Background(), "bob", "passw0rd-long2", false); err != nil {
		t.Fatal(err)
	}
	tok := func(user, pw string) string {
		rec := e.do("POST", "/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, user, pw))
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return "Bearer " + m["access_token"].(string)
	}
	return &syncEnv{e, tok("alice", "passw0rd-long"), tok("bob", "passw0rd-long2")}
}

func (s *syncEnv) push(t *testing.T, who, body string, wantCode int) map[string]any {
	t.Helper()
	rec := s.do("POST", "/sync/push", body, "Authorization", who)
	if rec.Code != wantCode {
		t.Fatalf("push: got %d want %d: %s", rec.Code, wantCode, rec.Body)
	}
	var m map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m)
	return m
}

func (s *syncEnv) pull(t *testing.T, who, query string) syncstore.PullResult {
	t.Helper()
	rec := s.do("GET", "/sync/pull"+query, "", "Authorization", who)
	if rec.Code != 200 {
		t.Fatalf("pull: %d %s", rec.Code, rec.Body)
	}
	var r syncstore.PullResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func statuses(m map[string]any) []string {
	var out []string
	for _, r := range m["results"].([]any) {
		out = append(out, r.(map[string]any)["status"].(string))
	}
	return out
}

func prof(id string, ts int64, extra string) string {
	return fmt.Sprintf(`{"id":%q,"collection":"c1","client_updated_at":%d,"payload":{"name":"req","auth":{"token":"t"}%s}}`, id, ts, extra)
}

func TestSyncRequiresAuth(t *testing.T) {
	s := newSyncEnv(t)
	if c := s.do("GET", "/sync/pull", "").Code; c != 401 {
		t.Fatalf("pull no token: %d", c)
	}
	if c := s.do("POST", "/sync/push", `{}`).Code; c != 401 {
		t.Fatalf("push no token: %d", c)
	}
	if c := s.do("GET", "/sync/pull", "", "Authorization", "Bearer garbage").Code; c != 401 {
		t.Fatalf("pull bad token: %d", c)
	}
}

func TestSyncRoundtripIdempotentTombstone(t *testing.T) {
	s := newSyncEnv(t)
	body := `{"profiles":[` + prof(idA, 1000, "") + `],"environments":[{"id":"` + idE + `","name":"prod","client_updated_at":1000,"payload":{"variables":{"k":"v"}}}]}`
	m := s.push(t, s.alice, body, 200)
	if got := statuses(m); got[0] != "applied" || got[1] != "applied" || m["cursor"].(float64) != 2 {
		t.Fatalf("first push: %v", m)
	}
	// Idempotent: same push again changes nothing.
	m = s.push(t, s.alice, body, 200)
	if got := statuses(m); got[0] != "skipped" || got[1] != "skipped" || m["cursor"].(float64) != 2 {
		t.Fatalf("second push: %v", m)
	}
	p := s.pull(t, s.alice, "")
	if len(p.Items) != 2 || p.Cursor != 2 || p.HasMore {
		t.Fatalf("pull: %+v", p)
	}
	if p.Items[0].Kind != "profile" || p.Items[0].Label != "c1" || !strings.Contains(string(p.Items[0].Payload), `"token":"t"`) {
		t.Fatalf("profile item: %+v", p.Items[0])
	}
	// Nothing new after the cursor.
	if p2 := s.pull(t, s.alice, "?since=2"); len(p2.Items) != 0 || p2.Cursor != 2 {
		t.Fatalf("empty pull: %+v", p2)
	}
	// Delete -> tombstone is pulled.
	s.push(t, s.alice, fmt.Sprintf(`{"profiles":[{"id":%q,"deleted":true,"client_updated_at":2000}]}`, idA), 200)
	p = s.pull(t, s.alice, "?since=2")
	if len(p.Items) != 1 || !p.Items[0].Deleted || p.Items[0].ID != idA || p.Items[0].Payload != nil || p.Cursor != 3 {
		t.Fatalf("tombstone pull: %+v", p)
	}
	// Stale re-push of the live item loses to the tombstone.
	m = s.push(t, s.alice, `{"profiles":[`+prof(idA, 1500, "")+`]}`, 200)
	if statuses(m)[0] != "conflict" {
		t.Fatalf("stale after delete: %v", m)
	}
	// Newer live copy resurrects.
	m = s.push(t, s.alice, `{"profiles":[`+prof(idA, 3000, "")+`]}`, 200)
	if statuses(m)[0] != "applied" {
		t.Fatalf("resurrect: %v", m)
	}
}

func TestSyncLWWConflict(t *testing.T) {
	s := newSyncEnv(t)
	s.push(t, s.alice, `{"profiles":[`+prof(idA, 2000, `,"v":"new"`)+`]}`, 200)
	m := s.push(t, s.alice, `{"profiles":[`+prof(idA, 1000, `,"v":"old"`)+`]}`, 200)
	r := m["results"].([]any)[0].(map[string]any)
	if r["status"] != "conflict" || r["server_version"].(float64) != 1 {
		t.Fatalf("conflict result: %v", r)
	}
	srv := r["server"].(map[string]any)
	if srv["client_updated_at"].(float64) != 2000 || !strings.Contains(fmt.Sprint(srv["payload"]), "new") {
		t.Fatalf("conflict server copy: %v", srv)
	}
	if m["cursor"].(float64) != 1 {
		t.Fatalf("conflict must not bump cursor: %v", m)
	}
	// Equal timestamp: deterministic regardless of order.
	s2 := newSyncEnv(t)
	s2.push(t, s2.alice, `{"profiles":[`+prof(idB, 5, `,"v":"b"`)+`]}`, 200)
	if st := statuses(s2.push(t, s2.alice, `{"profiles":[`+prof(idB, 5, `,"v":"a"`)+`]}`, 200))[0]; st != "conflict" {
		t.Fatalf("tie smaller should lose: %s", st)
	}
	if st := statuses(s2.push(t, s2.alice, `{"profiles":[`+prof(idB, 5, `,"v":"c"`)+`]}`, 200))[0]; st != "applied" {
		t.Fatalf("tie larger should win: %s", st)
	}
}

func TestSyncCursorMonotonicAndPagination(t *testing.T) {
	s := newSyncEnv(t)
	var sb strings.Builder
	for i := 0; i < 5; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(prof(fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i), int64(100+i), ""))
	}
	s.push(t, s.alice, `{"profiles":[`+sb.String()+`]}`, 200)
	var got []string
	var cursor int64
	var last int64
	for pages := 0; ; pages++ {
		p := s.pull(t, s.alice, fmt.Sprintf("?since=%d&limit=2", cursor))
		for _, it := range p.Items {
			if it.ServerVersion <= last {
				t.Fatalf("versions not increasing: %d after %d", it.ServerVersion, last)
			}
			last = it.ServerVersion
			got = append(got, it.ID)
		}
		if p.Cursor < cursor {
			t.Fatal("cursor went backwards")
		}
		cursor = p.Cursor
		if !p.HasMore {
			if pages != 2 {
				t.Fatalf("expected 3 pages, got %d", pages+1)
			}
			break
		}
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(got) != 5 || cursor != 5 {
		t.Fatalf("got %v cursor %d", got, cursor)
	}
	// An update bumps the cursor above everything seen.
	s.push(t, s.alice, `{"profiles":[`+prof("00000000-0000-4000-8000-000000000000", 999, "")+`]}`, 200)
	if p := s.pull(t, s.alice, "?since=5"); len(p.Items) != 1 || p.Cursor != 6 {
		t.Fatalf("update pull: %+v", p)
	}
}

func TestSyncUserIsolation(t *testing.T) {
	s := newSyncEnv(t)
	s.push(t, s.alice, `{"profiles":[`+prof(idA, 1000, `,"secret":"alice"`)+`]}`, 200)
	if p := s.pull(t, s.bob, ""); len(p.Items) != 0 || p.Cursor != 0 {
		t.Fatalf("bob sees alice data: %+v", p)
	}
	// Same client id for bob is an independent record; bob's delete does not touch alice's.
	m := s.push(t, s.bob, `{"profiles":[`+prof(idA, 10, `,"secret":"bob"`)+`]}`, 200)
	if statuses(m)[0] != "applied" {
		t.Fatalf("bob push: %v", m)
	}
	s.push(t, s.bob, fmt.Sprintf(`{"profiles":[{"id":%q,"deleted":true,"client_updated_at":20}]}`, idA), 200)
	p := s.pull(t, s.alice, "")
	if len(p.Items) != 1 || p.Items[0].Deleted || !strings.Contains(string(p.Items[0].Payload), `"alice"`) {
		t.Fatalf("alice data affected by bob: %+v", p)
	}
}

func TestSyncValidation(t *testing.T) {
	s := newSyncEnv(t)
	big := `"` + strings.Repeat("x", maxPayloadBytes) + `"`
	var many strings.Builder
	for i := 0; i <= maxPushItems; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(prof(fmt.Sprintf("00000000-0000-4000-8000-%012d", i), 1, ""))
	}
	for _, tc := range []struct {
		name, body string
		code       int
		err        string
	}{
		{"bad uuid", `{"profiles":[` + prof("not-a-uuid", 1, "") + `]}`, 400, "invalid_id"},
		{"missing ts", `{"profiles":[{"id":"` + idA + `","payload":{}}]}`, 400, "invalid_client_updated_at"},
		{"payload not object", `{"profiles":[{"id":"` + idA + `","client_updated_at":1,"payload":[1]}]}`, 400, "invalid_payload"},
		{"missing payload", `{"profiles":[{"id":"` + idA + `","client_updated_at":1}]}`, 400, "invalid_payload"},
		{"payload too big", `{"profiles":[` + prof(idA, 1, `,"b":`+big) + `]}`, 413, "item_too_large"},
		{"label too long", `{"environments":[{"id":"` + idE + `","name":"` + strings.Repeat("n", 256) + `","client_updated_at":1,"payload":{}}]}`, 400, "invalid_label"},
		{"duplicate id", `{"profiles":[` + prof(idA, 1, "") + `,` + prof(strings.ToUpper(idA), 2, "") + `]}`, 400, "duplicate_id"},
		{"too many items", `{"profiles":[` + many.String() + `]}`, 413, "too_many_items"},
		{"bad json", `{`, 400, "invalid_request"},
		{"body too large", `{"profiles":[],"pad":"` + strings.Repeat("x", maxPushBodyBytes) + `"}`, 413, "payload_too_large"},
	} {
		rec := s.do("POST", "/sync/push", tc.body, "Authorization", s.alice)
		if rec.Code != tc.code || errCode(t, rec) != tc.err {
			t.Errorf("%s: got %d %s, want %d %s", tc.name, rec.Code, rec.Body, tc.code, tc.err)
		}
	}
	// Nothing from the rejected requests was stored.
	if p := s.pull(t, s.alice, ""); len(p.Items) != 0 {
		t.Fatalf("rejected pushes stored data: %+v", p)
	}
	for _, q := range []string{"?since=-1", "?since=abc", "?limit=0", "?limit=1001", "?limit=x"} {
		if c := s.do("GET", "/sync/pull"+q, "", "Authorization", s.alice).Code; c != 400 {
			t.Errorf("pull%s: got %d want 400", q, c)
		}
	}
}
