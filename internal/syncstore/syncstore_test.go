package syncstore

import "testing"

func TestDecide(t *testing.T) {
	live := func(ts int64, label, payload string) Item {
		return Item{ClientUpdatedAt: ts, Label: label, Payload: []byte(payload)}
	}
	tomb := func(ts int64) Item { return Item{ClientUpdatedAt: ts, Deleted: true} }
	cur := live(100, "a", `{"x":1}`)
	tcur := tomb(100)
	for _, tc := range []struct {
		name string
		cur  *Item
		in   Item
		want Decision
	}{
		{"no current", nil, live(1, "", `{}`), Apply},
		{"newer", &cur, live(101, "a", `{"x":2}`), Apply},
		{"older", &cur, live(99, "a", `{"x":2}`), Conflict},
		{"identical", &cur, live(100, "a", `{"x":1}`), Unchanged},
		{"tie larger payload wins", &cur, live(100, "a", `{"x":2}`), Apply},
		{"tie smaller payload loses", &cur, live(100, "a", `{"x":0}`), Conflict},
		{"tie tombstone beats live", &cur, tomb(100), Apply},
		{"tie live loses to tombstone", &tcur, live(100, "a", `{}`), Conflict},
		{"tombstone twice", &tcur, tomb(100), Unchanged},
		{"older tombstone", &cur, tomb(50), Conflict},
		{"newer live resurrects", &tcur, live(101, "a", `{}`), Apply},
	} {
		if got := Decide(tc.cur, tc.in); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}
