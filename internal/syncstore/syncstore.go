// Package syncstore holds the sync data model, the conflict rules and the MySQL store.
package syncstore

import (
	"bytes"
	"context"
	"encoding/json"
)

const (
	KindProfile     = "profile"
	KindEnvironment = "environment"
)

// Item is one synced record. Payload is the client's JSON, stored as sent
// (compacted). Tombstones (Deleted) carry no payload.
type Item struct {
	Kind            string          `json:"kind"`
	ID              string          `json:"id"`
	Label           string          `json:"label,omitempty"` // profile: collection, environment: name
	Payload         json.RawMessage `json:"payload,omitempty"`
	ClientUpdatedAt int64           `json:"client_updated_at"` // unix ms, client clock; LWW only
	Deleted         bool            `json:"deleted"`
	ServerVersion   int64           `json:"server_version"`
}

const (
	StatusApplied  = "applied"
	StatusSkipped  = "skipped"  // identical to what the server already has
	StatusConflict = "conflict" // server copy wins; Result.Server holds it
)

type Result struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Status        string `json:"status"`
	ServerVersion int64  `json:"server_version"`
	Server        *Item  `json:"server,omitempty"`
}

type PushResult struct {
	Results []Result `json:"results"`
	Cursor  int64    `json:"cursor"`
}

type PullResult struct {
	Items   []Item `json:"items"`
	Cursor  int64  `json:"cursor"`
	HasMore bool   `json:"has_more"`
}

type Store interface {
	// Pull returns up to limit items with server_version > since in version order,
	// stopping early once maxBytes of payload is collected (always at least one item).
	Pull(ctx context.Context, userID, since int64, limit, maxBytes int) (*PullResult, error)
	// Push applies items atomically for one user. Item versions are assigned by the store.
	Push(ctx context.Context, userID int64, items []Item) (*PushResult, error)
}

type Decision int

const (
	Apply Decision = iota
	Unchanged
	Conflict
)

// Decide implements last-write-wins on ClientUpdatedAt. cur is the stored copy (nil if none).
// On equal timestamps the outcome is deterministic and independent of arrival order:
// identical content is Unchanged; otherwise a tombstone beats a live copy, and between
// two live copies the larger (label, payload) byte string wins.
func Decide(cur *Item, in Item) Decision {
	if cur == nil {
		return Apply
	}
	switch {
	case in.ClientUpdatedAt > cur.ClientUpdatedAt:
		return Apply
	case in.ClientUpdatedAt < cur.ClientUpdatedAt:
		return Conflict
	}
	if cur.Deleted && in.Deleted {
		return Unchanged
	}
	if cur.Deleted != in.Deleted {
		if in.Deleted {
			return Apply
		}
		return Conflict
	}
	c := bytes.Compare([]byte(in.Label+"\x00"+string(in.Payload)), []byte(cur.Label+"\x00"+string(cur.Payload)))
	switch {
	case c == 0:
		return Unchanged
	case c > 0:
		return Apply
	}
	return Conflict
}
