// Package store keeps the master's records in one SQLite file: applications,
// publishers and the masters' opinions of them, keys, servers, the request
// nonces seen, peers' synchronisation, the netlist and its sources' last
// good copies, the player keys' links to Discord accounts, and the audit
// log.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

// ErrNotFound is returned for a record that does not exist.
var ErrNotFound = errors.New("not found")

// Store is the database.
type Store struct {
	db  *sql.DB
	Now func() time.Time
	// the audit log's newest entries kept (AuditKeep)
	AuditKeep int
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS applications (
	id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, discord TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL, key_id TEXT NOT NULL, servers INTEGER NOT NULL, region TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '', proof_ok INTEGER NOT NULL DEFAULT 0, token_hash TEXT NOT NULL,
	email_verified INTEGER NOT NULL DEFAULT 0, address TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '', publisher_id TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL,
	updated INTEGER NOT NULL, address_key TEXT NOT NULL DEFAULT '', discord_id TEXT NOT NULL DEFAULT '',
	decided_by TEXT NOT NULL DEFAULT '', log_channel TEXT NOT NULL DEFAULT '', log_message TEXT NOT NULL DEFAULT '',
	log_status TEXT NOT NULL DEFAULT '', log_queued INTEGER NOT NULL DEFAULT 0, told_status TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS applications_key ON applications(key_id, created);
CREATE INDEX IF NOT EXISTS applications_address ON applications(address, created);
CREATE INDEX IF NOT EXISTS applications_token ON applications(token_hash);
CREATE INDEX IF NOT EXISTS applications_email ON applications(lower(email), created);
CREATE INDEX IF NOT EXISTS applications_created ON applications(created);
CREATE TABLE IF NOT EXISTS publishers (
	id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', discord TEXT NOT NULL DEFAULT '',
	origin TEXT NOT NULL, since INTEGER NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
	discord_id TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS opinions (
	publisher_id TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, quota INTEGER NOT NULL,
	reason TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL, PRIMARY KEY (publisher_id, source));
CREATE TABLE IF NOT EXISTS keys (
	key_id TEXT NOT NULL, source TEXT NOT NULL, publisher_id TEXT NOT NULL, public_key TEXT NOT NULL,
	status TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (key_id, source));
CREATE INDEX IF NOT EXISTS keys_publisher ON keys(publisher_id);
CREATE TABLE IF NOT EXISTS key_use (key_id TEXT PRIMARY KEY, last_used INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS servers (
	id TEXT PRIMARY KEY, publisher_id TEXT NOT NULL, key_id TEXT NOT NULL, instance TEXT NOT NULL,
	name TEXT NOT NULL, map TEXT NOT NULL, gametype TEXT NOT NULL, variant TEXT NOT NULL, players INTEGER NOT NULL,
	max_players INTEGER NOT NULL, teams INTEGER NOT NULL, in_progress INTEGER NOT NULL, password INTEGER NOT NULL,
	open INTEGER NOT NULL, dedicated INTEGER NOT NULL, kind INTEGER NOT NULL, engine INTEGER NOT NULL,
	network_version INTEGER NOT NULL, build TEXT NOT NULL, region TEXT NOT NULL, tunnel_port INTEGER NOT NULL,
	listing BLOB, host_key BLOB, sequence INTEGER NOT NULL, listing_time INTEGER NOT NULL,
	observed TEXT NOT NULL, declared TEXT NOT NULL, publish_address INTEGER NOT NULL, probe_address TEXT NOT NULL,
	probe TEXT NOT NULL, reachable INTEGER NOT NULL, probed_at INTEGER NOT NULL, hidden INTEGER NOT NULL,
	hidden_reason TEXT NOT NULL, trusted INTEGER NOT NULL, closed INTEGER NOT NULL, serial INTEGER NOT NULL,
	created INTEGER NOT NULL, updated INTEGER NOT NULL, listing_changed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS servers_publisher ON servers(publisher_id);
CREATE INDEX IF NOT EXISTS servers_updated ON servers(updated);
CREATE INDEX IF NOT EXISTS servers_host_key ON servers(host_key);
CREATE TABLE IF NOT EXISTS nonces (key_id TEXT NOT NULL, nonce TEXT NOT NULL, seen INTEGER NOT NULL,
	PRIMARY KEY (key_id, nonce));
CREATE INDEX IF NOT EXISTS nonces_seen ON nonces(seen);
CREATE TABLE IF NOT EXISTS audit (n INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, actor TEXT NOT NULL,
	action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_action ON audit(action, n);
CREATE TABLE IF NOT EXISTS peers (key_id TEXT PRIMARY KEY, url TEXT NOT NULL, since INTEGER NOT NULL,
	last_ok INTEGER NOT NULL, last_error TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS netlist_sources (id TEXT PRIMARY KEY, url TEXT NOT NULL, fetched INTEGER NOT NULL,
	ok INTEGER NOT NULL, error TEXT NOT NULL, entries INTEGER NOT NULL, data BLOB);
CREATE TABLE IF NOT EXISTS netlist_published (id INTEGER PRIMARY KEY CHECK (id = 1), serial INTEGER NOT NULL,
	generated INTEGER NOT NULL, built INTEGER NOT NULL, body BLOB NOT NULL, signature TEXT NOT NULL,
	ranges INTEGER NOT NULL, addresses INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS netlist_policy (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links (key TEXT PRIMARY KEY, key_id TEXT NOT NULL, discord_id TEXT NOT NULL,
	discord_name TEXT NOT NULL, created INTEGER NOT NULL, last_pass INTEGER NOT NULL, flags INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS links_discord ON links(discord_id);
CREATE INDEX IF NOT EXISTS links_key_id ON links(key_id);
CREATE TABLE IF NOT EXISTS link_pending (state TEXT PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,
	ts INTEGER NOT NULL, code TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS link_revoked (discord_id TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_by TEXT NOT NULL,
	at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS link_revoked_keys (key TEXT PRIMARY KEY, discord_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS link_revoked_keys_discord ON link_revoked_keys(discord_id);
`

// the indexes on columns a migration may have added
const lateIndexes = `
CREATE INDEX IF NOT EXISTS applications_address_key ON applications(address_key, created);
CREATE INDEX IF NOT EXISTS applications_discord ON applications(discord_id, created);
`

// columns added since the first schema, for databases made before them
var migrations = []struct{ table, column, declaration string }{
	{"applications", "address_key", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "discord_id", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "decided_by", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "log_channel", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "log_message", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "log_status", "TEXT NOT NULL DEFAULT ''"},
	{"applications", "log_queued", "INTEGER NOT NULL DEFAULT 0"},
	{"applications", "told_status", "TEXT NOT NULL DEFAULT ''"},
	{"servers", "listing_changed", "INTEGER NOT NULL DEFAULT 0"},
	{"publishers", "discord_id", "TEXT NOT NULL DEFAULT ''"},
}

// backfills fill a column added by a migration from the records made before
// it (run once, when the column is added).
var backfills = map[string]string{
	// (a publisher's Discord user id is its approved application's)
	"publishers.discord_id": `UPDATE publishers SET discord_id = COALESCE((SELECT a.discord_id FROM applications a
		WHERE a.publisher_id = publishers.id AND a.status = 'approved' AND a.discord_id != ''
		ORDER BY a.updated DESC LIMIT 1), '') WHERE discord_id = ''`,
}

// Connections is how many connections a database file is opened with:
// readers run beside each other (WAL), writers one at a time.
const Connections = 4

// Open opens (and makes, readable by its owner only) the database file.
func Open(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	connections := Connections
	if path == ":memory:" {
		// (one connection: each would have a database of its own)
		dsn, connections = "file::memory:?_pragma=busy_timeout(10000)", 1
	} else if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		// (SQLite gives its -wal and -shm files the database file's mode)
		f.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(connections)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("the database's schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("the database's schema: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO meta (k, v) VALUES ('schema', '1')`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, Now: time.Now, AuditKeep: AuditKeep}, nil
}

func migrate(db *sql.DB) error {
	for _, m := range migrations {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, m.table, m.column).
			Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE ` + m.table + ` ADD COLUMN ` + m.column + ` ` + m.declaration); err != nil {
				return err
			}
			if fill, ok := backfills[m.table+"."+m.column]; ok {
				if _, err := db.Exec(fill); err != nil {
					return err
				}
			}
		}
	}
	_, err := db.Exec(lateIndexes)
	return err
}

// DB is the database itself (tests, and maintenance).
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database answers.
func (s *Store) Ping() error {
	var one int
	return s.db.QueryRow(`SELECT 1`).Scan(&one)
}

func (s *Store) now() int64 { return s.Now().Unix() }

func boolean(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------- the audit log

// Audit records an action: who did it, what, to what, and why.
func (s *Store) Audit(actor, action, target, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit (time, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		s.now(), actor, action, target, detail)
	return err
}

// AuditLog returns the newest entries, before n when n > 0.
func (s *Store) AuditLog(limit int, before int64) ([]model.AuditEntry, error) {
	query := `SELECT n, time, actor, action, target, detail FROM audit`
	args := []any{}
	if before > 0 {
		query += ` WHERE n < ?`
		args = append(args, before)
	}
	query += ` ORDER BY n DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.N, &e.Time, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditActions returns the newest entries of an action at since or after,
// limit at most.
func (s *Store) AuditActions(action string, since int64, limit int) ([]model.AuditEntry, error) {
	rows, err := s.db.Query(`SELECT n, time, actor, action, target, detail FROM audit WHERE action = ? AND time >= ?
		ORDER BY n DESC LIMIT ?`, action, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.N, &e.Time, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- nonces

// UseNonce records a request's nonce; false if it was seen within window.
func (s *Store) UseNonce(keyID, nonce string, window time.Duration) (bool, error) {
	now := s.now()
	result, err := s.db.Exec(`INSERT INTO nonces (key_id, nonce, seen) VALUES (?, ?, ?)
		ON CONFLICT (key_id, nonce) DO UPDATE SET seen = excluded.seen WHERE nonces.seen < ?`,
		keyID, nonce, now, now-int64(window/time.Second))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// ---------- housekeeping

// What is kept for a time only.
const (
	// a closed server's record, from its closing
	ClosedRetention = time.Hour
	// a server's record that was not published again (unless an admin
	// flagged it)
	ExpiredRetention = 24 * time.Hour
	// a web form's application whose e-mail address was never verified,
	// still pending
	UnverifiedRetention = 7 * 24 * time.Hour
	// a denied application, from its denial
	DeniedRetention = 30 * 24 * time.Hour
	// the audit log's newest entries kept
	AuditKeep = 100000
	// a link page's visit waiting for Discord's answer
	LinkPendingRetention = 10 * time.Minute
	// a player key's link, from its last pass (or its making)
	LinkRetention = 90 * 24 * time.Hour
)

// Purge drops what is kept for a time only: nonces past their window,
// closed and expired servers, addresses past the address retention,
// the web form's applications never verified, applications long denied, the audit log's oldest
// entries past AuditKeep, link pages' visits past 10 minutes, and links 90 days unused.
func (s *Store) Purge(nonceWindow, addressRetention time.Duration) error {
	now := s.now()
	seconds := func(d time.Duration) int64 { return int64(d / time.Second) }
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM nonces WHERE seen < ?`, []any{now - seconds(nonceWindow)}},
		{`DELETE FROM servers WHERE hidden = 0 AND trusted = 0 AND ((closed = 1 AND updated < ?) OR updated < ?)`,
			[]any{now - seconds(ClosedRetention), now - seconds(ExpiredRetention)}},
		{`UPDATE servers SET observed = '', declared = '', probe_address = '' WHERE updated < ? AND
			(observed != '' OR declared != '' OR probe_address != '')`, []any{now - seconds(addressRetention)}},
		{`UPDATE applications SET address = '', address_key = '' WHERE created < ? AND
			(address != '' OR address_key != '')`, []any{now - seconds(addressRetention)}},
		{`DELETE FROM applications WHERE status = 'pending' AND email != '' AND email_verified = 0 AND created < ?`,
			[]any{now - seconds(UnverifiedRetention)}},
		{`DELETE FROM applications WHERE status = 'denied' AND updated < ?`, []any{now - seconds(DeniedRetention)}},
		{`DELETE FROM audit WHERE n <= (SELECT MAX(n) FROM audit) - ?`, []any{s.AuditKeep}},
		{`DELETE FROM link_pending WHERE created < ?`, []any{now - seconds(LinkPendingRetention)}},
		{`DELETE FROM links WHERE MAX(last_pass, created) < ?`, []any{now - seconds(LinkRetention)}},
	} {
		if _, err := s.db.Exec(statement.query, statement.args...); err != nil {
			return err
		}
	}
	return nil
}

// ---------- settings

// Setting returns a setting's value, and whether it is set.
func (s *Store) Setting(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT v FROM settings WHERE k = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

// SetSetting stores a setting; an empty value removes it.
func (s *Store) SetSetting(key, value string) error {
	if value == "" {
		_, err := s.db.Exec(`DELETE FROM settings WHERE k = ?`, key)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
		key, value)
	return err
}

// ---------- peers

// PeerState is what the master knows of its synchronisation with a peer.
type PeerState struct {
	KeyID     string
	URL       string
	Since     int64
	LastOK    int64
	LastError string
}

// Peer returns a peer's state (a zero state for a new one).
func (s *Store) Peer(keyID string) (PeerState, error) {
	p := PeerState{KeyID: keyID}
	err := s.db.QueryRow(`SELECT url, since, last_ok, last_error FROM peers WHERE key_id = ?`, keyID).
		Scan(&p.URL, &p.Since, &p.LastOK, &p.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return p, err
}

// SetPeer stores a peer's state.
func (s *Store) SetPeer(p PeerState) error {
	_, err := s.db.Exec(`INSERT INTO peers (key_id, url, since, last_ok, last_error) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (key_id) DO UPDATE SET url = excluded.url, since = excluded.since, last_ok = excluded.last_ok,
		last_error = excluded.last_error`, p.KeyID, p.URL, p.Since, p.LastOK, p.LastError)
	return err
}

// Peers returns every peer's state.
func (s *Store) Peers() ([]PeerState, error) {
	rows, err := s.db.Query(`SELECT key_id, url, since, last_ok, last_error FROM peers ORDER BY url`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerState
	for rows.Next() {
		var p PeerState
		if err := rows.Scan(&p.KeyID, &p.URL, &p.Since, &p.LastOK, &p.LastError); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
