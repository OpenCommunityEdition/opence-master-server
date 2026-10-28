package store

import (
	"database/sql"
	"errors"
	"strings"
)

// Link is a player key held by a Discord account.
type Link struct {
	// the player's public key, 64 hexadecimal digits
	Key         string
	KeyID       string
	DiscordID   string
	DiscordName string
	Created     int64
	// the last pass given (0: none yet)
	LastPass int64
	// the pass's flags (1: in the master's Discord server when it linked)
	Flags int
}

// Used is when the link was last used: its last pass, else its making.
func (l Link) Used() int64 {
	if l.LastPass > 0 {
		return l.LastPass
	}
	return l.Created
}

// PendingLink is a link page's visit, waiting for Discord's answer.
type PendingLink struct {
	// the OAuth state, random, the row's key (single use)
	State string
	// "link" (a key to link), or "manage" (a login to /link/manage)
	Kind string
	// the key to link and its ts (a link's)
	Key     string
	TS      int64
	Code    string
	Created int64
}

// The kinds of pending links.
const (
	PendingLinkKey    = "link"
	PendingLinkManage = "manage"
)

// Revocation is a Discord account the master's admins revoked: its keys
// get no pass, and it links no more.
type Revocation struct {
	DiscordID string
	Reason    string
	By        string
	At        int64
	// the keys it held when it was revoked
	Keys int
}

const linkColumns = `key, key_id, discord_id, discord_name, created, last_pass, flags`

func scanLinks(rows *sql.Rows) ([]Link, error) {
	defer rows.Close()
	var out []Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.Key, &l.KeyID, &l.DiscordID, &l.DiscordName, &l.Created, &l.LastPass,
			&l.Flags); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// AddPendingLink stores a link page's visit.
func (s *Store) AddPendingLink(p PendingLink) error {
	_, err := s.db.Exec(`INSERT INTO link_pending (state, kind, key, ts, code, created) VALUES (?, ?, ?, ?, ?, ?)`,
		p.State, p.Kind, p.Key, p.TS, p.Code, p.Created)
	return err
}

// TakePendingLink takes a visit by its state, once, if it was made since
// a time; ErrNotFound otherwise.
func (s *Store) TakePendingLink(state string, since int64) (*PendingLink, error) {
	p := PendingLink{State: state}
	err := s.db.QueryRow(`DELETE FROM link_pending WHERE state = ? RETURNING kind, key, ts, code, created`, state).
		Scan(&p.Kind, &p.Key, &p.TS, &p.Code, &p.Created)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && p.Created < since) {
		return nil, ErrNotFound
	}
	return &p, err
}

// LinkOf returns a key's link.
func (s *Store) LinkOf(key string) (*Link, error) {
	rows, err := s.db.Query(`SELECT `+linkColumns+` FROM links WHERE key = ?`, key)
	if err != nil {
		return nil, err
	}
	links, err := scanLinks(rows)
	if err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return nil, ErrNotFound
	}
	return &links[0], nil
}

// AccountLinks returns a Discord account's links, the most recently used
// first.
func (s *Store) AccountLinks(discordID string) ([]Link, error) {
	rows, err := s.db.Query(`SELECT `+linkColumns+` FROM links WHERE discord_id = ?
		ORDER BY MAX(last_pass, created) DESC, key`, discordID)
	if err != nil {
		return nil, err
	}
	return scanLinks(rows)
}

// SearchLinks returns the links whose Discord id, key id or key is the
// text, or whose Discord username holds it (the newest links for an empty
// text), limit at most.
func (s *Store) SearchLinks(text string, limit int) ([]Link, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		rows, err := s.db.Query(`SELECT `+linkColumns+` FROM links ORDER BY created DESC LIMIT ?`, limit)
		if err != nil {
			return nil, err
		}
		return scanLinks(rows)
	}
	like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(text)) + "%"
	key := strings.TrimPrefix(strings.ToLower(text), "ed25519:")
	rows, err := s.db.Query(`SELECT `+linkColumns+` FROM links WHERE discord_id = ? OR key_id = ? OR key = ?
		OR lower(discord_name) LIKE ? ESCAPE '\' ORDER BY discord_id, created DESC LIMIT ?`, text, key, key, like, limit)
	if err != nil {
		return nil, err
	}
	return scanLinks(rows)
}

// SaveLink records a key as an account's: a link of the key to another
// account is replaced, and past maximum keys the account's least recently
// used ones are dropped. It returns the account the key was taken from
// (empty if none) and the keys dropped.
func (s *Store) SaveLink(l Link, maximum int) (replaced string, dropped []Link, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	err = tx.QueryRow(`SELECT discord_id FROM links WHERE key = ?`, l.Key).Scan(&replaced)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}
	if replaced == l.DiscordID {
		replaced = ""
	}
	if _, err := tx.Exec(`INSERT INTO links (`+linkColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET key_id = excluded.key_id, discord_id = excluded.discord_id,
		discord_name = excluded.discord_name, created = excluded.created, last_pass = 0, flags = excluded.flags`,
		l.Key, l.KeyID, l.DiscordID, l.DiscordName, l.Created, l.LastPass, l.Flags); err != nil {
		return "", nil, err
	}
	// (a new login refreshes the account's other keys' username and flags)
	if _, err := tx.Exec(`UPDATE links SET discord_name = ?, flags = ? WHERE discord_id = ?`, l.DiscordName,
		l.Flags, l.DiscordID); err != nil {
		return "", nil, err
	}
	rows, err := tx.Query(`SELECT `+linkColumns+` FROM links WHERE discord_id = ? AND key != ?
		ORDER BY MAX(last_pass, created) DESC, key`, l.DiscordID, l.Key)
	if err != nil {
		return "", nil, err
	}
	others, err := scanLinks(rows)
	if err != nil {
		return "", nil, err
	}
	if maximum > 0 && len(others) > maximum-1 {
		dropped = others[maximum-1:]
		for _, d := range dropped {
			if _, err := tx.Exec(`DELETE FROM links WHERE key = ?`, d.Key); err != nil {
				return "", nil, err
			}
		}
	}
	return replaced, dropped, tx.Commit()
}

// DeleteLink deletes a key's link (only an account's, when discordID is
// set); false if there was none.
func (s *Store) DeleteLink(key, discordID string) (bool, error) {
	query, args := `DELETE FROM links WHERE key = ?`, []any{key}
	if discordID != "" {
		query += ` AND discord_id = ?`
		args = append(args, discordID)
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}

// DeleteAccountLinks deletes every link of an account, returning how many.
func (s *Store) DeleteAccountLinks(discordID string) (int, error) {
	result, err := s.db.Exec(`DELETE FROM links WHERE discord_id = ?`, discordID)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	return int(n), err
}

// TouchPass records a pass given for a key.
func (s *Store) TouchPass(key string, at int64) error {
	_, err := s.db.Exec(`UPDATE links SET last_pass = ? WHERE key = ?`, at, key)
	return err
}

// Revoke revokes a Discord account: its links are deleted, its keys
// remembered as revoked (a pass asked for one is refused with the reason),
// and it links no more. It returns how many keys it held.
func (s *Store) Revoke(r Revocation) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO link_revoked (discord_id, reason, revoked_by, at) VALUES (?, ?, ?, ?)
		ON CONFLICT (discord_id) DO UPDATE SET reason = excluded.reason, revoked_by = excluded.revoked_by, at = excluded.at`,
		r.DiscordID, r.Reason, r.By, r.At); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO link_revoked_keys (key, discord_id)
		SELECT key, discord_id FROM links WHERE discord_id = ?`, r.DiscordID); err != nil {
		return 0, err
	}
	result, err := tx.Exec(`DELETE FROM links WHERE discord_id = ?`, r.DiscordID)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), tx.Commit()
}

// Revocation returns an account's revocation (nil if it is not revoked).
func (s *Store) Revocation(discordID string) (*Revocation, error) {
	r := Revocation{DiscordID: discordID}
	err := s.db.QueryRow(`SELECT reason, revoked_by, at FROM link_revoked WHERE discord_id = ?`, discordID).
		Scan(&r.Reason, &r.By, &r.At)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// KeyRevocation returns the revocation of the account that held a key when
// it was revoked (nil if none).
func (s *Store) KeyRevocation(key string) (*Revocation, error) {
	var r Revocation
	err := s.db.QueryRow(`SELECT r.discord_id, r.reason, r.revoked_by, r.at FROM link_revoked_keys k
		JOIN link_revoked r ON r.discord_id = k.discord_id WHERE k.key = ?`, key).Scan(&r.DiscordID, &r.Reason,
		&r.By, &r.At)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// Revocations returns every revoked account, the newest first.
func (s *Store) Revocations() ([]Revocation, error) {
	rows, err := s.db.Query(`SELECT r.discord_id, r.reason, r.revoked_by, r.at,
		(SELECT COUNT(*) FROM link_revoked_keys k WHERE k.discord_id = r.discord_id) FROM link_revoked r
		ORDER BY r.at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.DiscordID, &r.Reason, &r.By, &r.At, &r.Keys); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LiftRevocation lifts an account's revocation (its keys must be linked
// again); false if it was not revoked.
func (s *Store) LiftRevocation(discordID string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM link_revoked WHERE discord_id = ?`, discordID)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM link_revoked_keys WHERE discord_id = ?`, discordID); err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, tx.Commit()
}
