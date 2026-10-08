package syncstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type MySQLStore struct{ db *sql.DB }

func NewMySQLStore(db *sql.DB) *MySQLStore { return &MySQLStore{db: db} }

var tables = map[string]string{KindProfile: "sync_profiles", KindEnvironment: "sync_environments"}

func (s *MySQLStore) Pull(ctx context.Context, userID, since int64, limit, maxBytes int) (*PullResult, error) {
	q := func(kind, table string) string {
		return fmt.Sprintf("(SELECT '%s' AS kind, id, label, payload, client_updated_at, deleted, server_version FROM %s "+
			"WHERE user_id = ? AND server_version > ? ORDER BY server_version LIMIT ?)", kind, table)
	}
	query := q(KindProfile, "sync_profiles") + " UNION ALL " + q(KindEnvironment, "sync_environments") +
		" ORDER BY server_version LIMIT ?"
	n := limit + 1
	// Read-only tx = one consistent snapshot across both tables.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, query, userID, since, n, userID, since, n, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := &PullResult{Items: []Item{}, Cursor: since}
	size := 0
	for rows.Next() {
		var it Item
		var payload sql.NullString
		if err := rows.Scan(&it.Kind, &it.ID, &it.Label, &payload, &it.ClientUpdatedAt, &it.Deleted, &it.ServerVersion); err != nil {
			return nil, err
		}
		if len(res.Items) >= limit || (len(res.Items) > 0 && size+len(payload.String) > maxBytes) {
			res.HasMore = true
			break
		}
		if payload.Valid && !it.Deleted {
			it.Payload = []byte(payload.String)
		}
		size += len(payload.String)
		res.Items = append(res.Items, it)
		res.Cursor = it.ServerVersion
	}
	return res, rows.Err()
}

func (s *MySQLStore) Push(ctx context.Context, userID int64, items []Item) (*PushResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// The counter row lock serialises pushes per user: versions are assigned in
	// commit order, so a reader never sees version N before a lower one commits.
	if _, err := tx.ExecContext(ctx, "INSERT INTO sync_counters (user_id, version) VALUES (?, 0) ON DUPLICATE KEY UPDATE version = version", userID); err != nil {
		return nil, err
	}
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT version FROM sync_counters WHERE user_id = ? FOR UPDATE", userID).Scan(&version); err != nil {
		return nil, err
	}
	start := version
	out := &PushResult{Results: make([]Result, 0, len(items))}
	for _, in := range items {
		table, ok := tables[in.Kind]
		if !ok {
			return nil, fmt.Errorf("unknown kind %q", in.Kind)
		}
		cur, err := getItem(ctx, tx, table, in.Kind, userID, in.ID)
		if err != nil {
			return nil, err
		}
		r := Result{Kind: in.Kind, ID: in.ID}
		switch Decide(cur, in) {
		case Unchanged:
			r.Status, r.ServerVersion = StatusSkipped, cur.ServerVersion
		case Conflict:
			r.Status, r.ServerVersion, r.Server = StatusConflict, cur.ServerVersion, cur
		case Apply:
			version++
			if err := upsert(ctx, tx, table, userID, in, version); err != nil {
				return nil, err
			}
			r.Status, r.ServerVersion = StatusApplied, version
		}
		out.Results = append(out.Results, r)
	}
	if version != start {
		if _, err := tx.ExecContext(ctx, "UPDATE sync_counters SET version = ? WHERE user_id = ?", version, userID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out.Cursor = version
	return out, nil
}

func getItem(ctx context.Context, tx *sql.Tx, table, kind string, userID int64, id string) (*Item, error) {
	it := Item{Kind: kind, ID: id}
	var payload sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT label, payload, client_updated_at, deleted, server_version FROM "+table+
		" WHERE user_id = ? AND id = ? FOR UPDATE", userID, id).
		Scan(&it.Label, &payload, &it.ClientUpdatedAt, &it.Deleted, &it.ServerVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if payload.Valid && !it.Deleted {
		it.Payload = []byte(payload.String)
	}
	return &it, nil
}

func upsert(ctx context.Context, tx *sql.Tx, table string, userID int64, in Item, version int64) error {
	var payload any
	var deletedAt any
	label := in.Label
	if in.Deleted {
		deletedAt = time.Now().UTC()
		label = ""
	} else {
		payload = string(in.Payload)
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (user_id, id, label, payload, client_updated_at, deleted, deleted_at, server_version) "+
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE label = VALUES(label), payload = VALUES(payload), "+
		"client_updated_at = VALUES(client_updated_at), deleted = VALUES(deleted), deleted_at = VALUES(deleted_at), server_version = VALUES(server_version)",
		userID, in.ID, label, payload, in.ClientUpdatedAt, in.Deleted, deletedAt, version)
	return err
}
