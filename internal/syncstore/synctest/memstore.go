// Package synctest provides an in-memory syncstore.Store mirroring the MySQL semantics.
package synctest

import (
	"context"
	"sort"
	"sync"

	"github.com/wantox86/KangPaket-server/internal/syncstore"
)

type key struct {
	user     int64
	kind, id string
}

type MemStore struct {
	mu       sync.Mutex
	items    map[key]syncstore.Item
	counters map[int64]int64
}

func NewMemStore() *MemStore {
	return &MemStore{items: map[key]syncstore.Item{}, counters: map[int64]int64{}}
}

func (m *MemStore) Pull(_ context.Context, userID, since int64, limit, maxBytes int) (*syncstore.PullResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []syncstore.Item
	for k, it := range m.items {
		if k.user == userID && it.ServerVersion > since {
			all = append(all, it)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ServerVersion < all[j].ServerVersion })
	res := &syncstore.PullResult{Items: []syncstore.Item{}, Cursor: since}
	size := 0
	for _, it := range all {
		if len(res.Items) >= limit || (len(res.Items) > 0 && size+len(it.Payload) > maxBytes) {
			res.HasMore = true
			break
		}
		size += len(it.Payload)
		res.Items = append(res.Items, it)
		res.Cursor = it.ServerVersion
	}
	return res, nil
}

func (m *MemStore) Push(_ context.Context, userID int64, items []syncstore.Item) (*syncstore.PushResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	version := m.counters[userID]
	out := &syncstore.PushResult{Results: []syncstore.Result{}}
	for _, in := range items {
		k := key{userID, in.Kind, in.ID}
		var cur *syncstore.Item
		if c, ok := m.items[k]; ok {
			cur = &c
		}
		r := syncstore.Result{Kind: in.Kind, ID: in.ID}
		switch syncstore.Decide(cur, in) {
		case syncstore.Unchanged:
			r.Status, r.ServerVersion = syncstore.StatusSkipped, cur.ServerVersion
		case syncstore.Conflict:
			r.Status, r.ServerVersion, r.Server = syncstore.StatusConflict, cur.ServerVersion, cur
		case syncstore.Apply:
			version++
			in.ServerVersion = version
			if in.Deleted {
				in.Payload, in.Label = nil, ""
			}
			m.items[k] = in
			r.Status, r.ServerVersion = syncstore.StatusApplied, version
		}
		out.Results = append(out.Results, r)
	}
	m.counters[userID] = version
	out.Cursor = version
	return out, nil
}
