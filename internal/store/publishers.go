package store

import (
	"database/sql"
	"errors"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

const applicationColumns = `id, name, email, discord, public_key, key_id, servers, region, note, proof_ok, token_hash,
	email_verified, address, status, reason, publisher_id, created, updated, address_key, discord_id, decided_by,
	log_channel, log_message, log_status, log_queued, told_status`

// the number of applicationColumns
const applicationColumnCount = 26

type scanner interface{ Scan(...any) error }

func scanApplication(row scanner) (*model.Application, error) {
	var a model.Application
	var proof, verified, queued int
	err := row.Scan(&a.ID, &a.Name, &a.Email, &a.Discord, &a.PublicKey, &a.KeyID, &a.Servers, &a.Region, &a.Note,
		&proof, &a.TokenHash, &verified, &a.Address, &a.Status, &a.Reason, &a.PublisherID, &a.Created, &a.Updated,
		&a.AddressKey, &a.DiscordID, &a.DecidedBy, &a.LogChannel, &a.LogMessage, &a.LogStatus, &queued, &a.ToldStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.ProofOK, a.EmailVerified, a.LogQueued = proof != 0, verified != 0, queued != 0
	return &a, err
}

func applicationValues(a *model.Application) []any {
	return []any{a.ID, a.Name, a.Email, a.Discord, a.PublicKey, a.KeyID, a.Servers, a.Region, a.Note,
		boolean(a.ProofOK), a.TokenHash, boolean(a.EmailVerified), a.Address, a.Status, a.Reason, a.PublisherID,
		a.Created, a.Updated, a.AddressKey, a.DiscordID, a.DecidedBy, a.LogChannel, a.LogMessage, a.LogStatus,
		boolean(a.LogQueued), a.ToldStatus}
}

// CreateApplication stores a new application.
func (s *Store) CreateApplication(a *model.Application) error {
	_, err := s.db.Exec(`INSERT INTO applications (`+applicationColumns+`) VALUES (`+
		placeholders(applicationColumnCount)+`)`, applicationValues(a)...)
	return err
}

// Application returns an application.
func (s *Store) Application(id string) (*model.Application, error) {
	return scanApplication(s.db.QueryRow(`SELECT `+applicationColumns+` FROM applications WHERE id = ?`, id))
}

func (s *Store) applications(query string, args ...any) ([]model.Application, error) {
	rows, err := s.db.Query(`SELECT `+applicationColumns+` FROM applications `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Application
	for rows.Next() {
		a, err := scanApplication(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// Applications returns the applications of a status ("" for all), newest
// first.
func (s *Store) Applications(status string, limit int) ([]model.Application, error) {
	if status == "" {
		return s.applications(`ORDER BY created DESC LIMIT ?`, limit)
	}
	return s.applications(`WHERE status = ? ORDER BY created DESC LIMIT ?`, status, limit)
}

// CountApplications counts the applications of a status.
func (s *Store) CountApplications(status string) (int, error) {
	return s.count(`status = ?`, status)
}

// RelatedApplications returns the other applications from the same Discord
// user or for the same key, and (the web form's) from the same address (its
// address key: an IPv6 address's /64) or with the same e-mail address.
func (s *Store) RelatedApplications(a *model.Application) ([]model.Application, error) {
	return s.applications(`WHERE id != ? AND (key_id = ? OR (discord_id != '' AND discord_id = ?) OR
		(email != '' AND lower(email) = lower(?)) OR (address_key != '' AND address_key = ?))
		ORDER BY created DESC LIMIT 50`, a.ID, a.KeyID, a.DiscordID, a.Email, a.AddressKey)
}

// LatestApplicationForKey returns the newest application for a key.
func (s *Store) LatestApplicationForKey(keyID string) (*model.Application, error) {
	return scanApplication(s.db.QueryRow(`SELECT `+applicationColumns+` FROM applications WHERE key_id = ?
		ORDER BY created DESC LIMIT 1`, keyID))
}

// PendingApplicationOfDiscord returns a Discord user's newest pending
// application.
func (s *Store) PendingApplicationOfDiscord(discordID string) (*model.Application, error) {
	return scanApplication(s.db.QueryRow(`SELECT `+applicationColumns+` FROM applications WHERE discord_id = ?
		AND status = 'pending' ORDER BY created DESC LIMIT 1`, discordID))
}

func (s *Store) count(query string, args ...any) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM applications WHERE `+query, args...).Scan(&n)
	return n, err
}

// ApplicationsOfDiscord counts a Discord user's applications since a time.
func (s *Store) ApplicationsOfDiscord(discordID string, since int64) (int, error) {
	return s.count(`discord_id = ? AND created >= ?`, discordID, since)
}

// ApplicationsForKey counts the applications for a key since a time.
func (s *Store) ApplicationsForKey(keyID string, since int64) (int, error) {
	return s.count(`key_id = ? AND created >= ?`, keyID, since)
}

// ApplicationsSince counts every application since a time.
func (s *Store) ApplicationsSince(since int64) (int, error) {
	return s.count(`created >= ?`, since)
}

// UnprovenApplicationsSince counts the applications without a proof of key
// since a time.
func (s *Store) UnprovenApplicationsSince(since int64) (int, error) {
	return s.count(`proof_ok = 0 AND created >= ?`, since)
}

// SetApplicationStatus records a decision on an application, and who made
// it.
func (s *Store) SetApplicationStatus(id, status, reason, publisherID, decidedBy string) error {
	_, err := s.db.Exec(`UPDATE applications SET status = ?, reason = ?, publisher_id = ?, decided_by = ?, updated = ?
		WHERE id = ?`, status, reason, publisherID, decidedBy, s.now(), id)
	return err
}

// ApplicationsToSync returns, oldest first, the applications the Discord bot
// has work for: one still to be posted to the log channel, one whose posted
// message shows another status than its own, and one whose Discord
// applicant was not told of its status.
func (s *Store) ApplicationsToSync(limit int) ([]model.Application, error) {
	return s.applications(`WHERE log_queued = 1 OR (log_message != '' AND log_status != status) OR
		(discord_id != '' AND told_status != status) ORDER BY created LIMIT ?`, limit)
}

// SetApplicationPosted records an application's log channel message (none,
// to take it off the queue unposted) and the status it shows.
func (s *Store) SetApplicationPosted(id, channel, message, status string) error {
	_, err := s.db.Exec(`UPDATE applications SET log_channel = ?, log_message = ?, log_status = ?, log_queued = 0
		WHERE id = ?`, channel, message, status, id)
	return err
}

// SetApplicationShown records the status an application's log channel
// message shows.
func (s *Store) SetApplicationShown(id, status string) error {
	_, err := s.db.Exec(`UPDATE applications SET log_status = ? WHERE id = ?`, status, id)
	return err
}

// SetApplicationTold records the status a Discord applicant was told of.
func (s *Store) SetApplicationTold(id, status string) error {
	_, err := s.db.Exec(`UPDATE applications SET told_status = ? WHERE id = ?`, status, id)
	return err
}

// ---------- publishers

func scanPublisher(row scanner) (*model.Publisher, error) {
	var p model.Publisher
	err := row.Scan(&p.ID, &p.Name, &p.Email, &p.Discord, &p.Origin, &p.Since, &p.Created, &p.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

const publisherColumns = `id, name, email, discord, origin, since, created, updated`

// Publisher returns a publisher's record.
func (s *Store) Publisher(id string) (*model.Publisher, error) {
	return scanPublisher(s.db.QueryRow(`SELECT `+publisherColumns+` FROM publishers WHERE id = ?`, id))
}

// Publishers returns every publisher's record.
func (s *Store) Publishers() ([]model.Publisher, error) {
	rows, err := s.db.Query(`SELECT ` + publisherColumns + ` FROM publishers ORDER BY since, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Publisher
	for rows.Next() {
		p, err := scanPublisher(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PutPublisher inserts a publisher, or updates its name, contact and time.
func (s *Store) PutPublisher(p *model.Publisher) error {
	_, err := s.db.Exec(`INSERT INTO publishers (`+publisherColumns+`) VALUES (`+placeholders(8)+`)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, email = excluded.email, discord = excluded.discord,
		updated = excluded.updated`, p.ID, p.Name, p.Email, p.Discord, p.Origin, p.Since, p.Created, p.Updated)
	return err
}

// InsertPublisherIfAbsent inserts a publisher unless one has its id.
func (s *Store) InsertPublisherIfAbsent(p *model.Publisher) (bool, error) {
	result, err := s.db.Exec(`INSERT OR IGNORE INTO publishers (`+publisherColumns+`) VALUES (`+placeholders(8)+`)`,
		p.ID, p.Name, p.Email, p.Discord, p.Origin, p.Since, p.Created, p.Updated)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// SetPublisherName renames a publisher.
func (s *Store) SetPublisherName(id, name string, updated int64) error {
	_, err := s.db.Exec(`UPDATE publishers SET name = ?, updated = ? WHERE id = ?`, name, updated, id)
	return err
}

// ---------- opinions

// Opinions returns the opinions of a publisher ("" for every publisher's).
func (s *Store) Opinions(publisherID string) ([]model.Opinion, error) {
	query := `SELECT publisher_id, source, status, quota, reason, updated FROM opinions`
	args := []any{}
	if publisherID != "" {
		query += ` WHERE publisher_id = ?`
		args = append(args, publisherID)
	}
	rows, err := s.db.Query(query+` ORDER BY publisher_id, source`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Opinion
	for rows.Next() {
		var o model.Opinion
		if err := rows.Scan(&o.PublisherID, &o.Source, &o.Status, &o.Quota, &o.Reason, &o.Updated); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetOpinion stores a master's opinion, replacing its earlier one.
func (s *Store) SetOpinion(o model.Opinion) error {
	_, err := s.db.Exec(`INSERT INTO opinions (publisher_id, source, status, quota, reason, updated)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (publisher_id, source) DO UPDATE SET status = excluded.status,
		quota = excluded.quota, reason = excluded.reason, updated = excluded.updated`,
		o.PublisherID, o.Source, o.Status, o.Quota, o.Reason, o.Updated)
	return err
}

// MergeOpinion stores an opinion if it is newer than the one stored.
func (s *Store) MergeOpinion(o model.Opinion) (bool, error) {
	var status string
	var updated int64
	err := s.db.QueryRow(`SELECT status, updated FROM opinions WHERE publisher_id = ? AND source = ?`,
		o.PublisherID, o.Source).Scan(&status, &updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil && !model.Newer(o.Updated, updated, o.Status, status) {
		return false, nil
	}
	return true, s.SetOpinion(o)
}

// ---------- keys

const keyColumns = `key_id, source, publisher_id, public_key, status, updated`

func (s *Store) keyRecords(query string, args ...any) ([]model.KeyRecord, error) {
	rows, err := s.db.Query(`SELECT `+keyColumns+` FROM keys `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.KeyRecord
	for rows.Next() {
		var k model.KeyRecord
		if err := rows.Scan(&k.KeyID, &k.Source, &k.PublisherID, &k.PublicKey, &k.Status, &k.Updated); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// KeyRecords returns every master's record of a key.
func (s *Store) KeyRecords(keyID string) ([]model.KeyRecord, error) {
	return s.keyRecords(`WHERE key_id = ? ORDER BY source`, keyID)
}

// PublisherKeys returns the key records of a publisher ("" for all).
func (s *Store) PublisherKeys(publisherID string) ([]model.KeyRecord, error) {
	if publisherID == "" {
		return s.keyRecords(`ORDER BY publisher_id, key_id, source`)
	}
	return s.keyRecords(`WHERE publisher_id = ? ORDER BY key_id, source`, publisherID)
}

// SetKey stores a master's record of a key.
func (s *Store) SetKey(k model.KeyRecord) error {
	_, err := s.db.Exec(`INSERT INTO keys (`+keyColumns+`) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (key_id, source) DO UPDATE SET publisher_id = excluded.publisher_id,
		public_key = excluded.public_key, status = excluded.status, updated = excluded.updated`,
		k.KeyID, k.Source, k.PublisherID, k.PublicKey, k.Status, k.Updated)
	return err
}

// MergeKey stores a key record if it is newer than the one stored; a
// revoked key stays revoked.
func (s *Store) MergeKey(k model.KeyRecord) (bool, error) {
	var status string
	var updated int64
	err := s.db.QueryRow(`SELECT status, updated FROM keys WHERE key_id = ? AND source = ?`, k.KeyID, k.Source).
		Scan(&status, &updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil {
		if status == model.KeyRevoked || !model.Newer(k.Updated, updated, k.Status, status) {
			return false, nil
		}
	}
	return true, s.SetKey(k)
}

// TouchKey records a key's use.
func (s *Store) TouchKey(keyID string) error {
	_, err := s.db.Exec(`INSERT INTO key_use (key_id, last_used) VALUES (?, ?)
		ON CONFLICT (key_id) DO UPDATE SET last_used = excluded.last_used`, keyID, s.now())
	return err
}

// KeyLastUsed returns when each of some keys was last used.
func (s *Store) KeyLastUsed(keyIDs []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(keyIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(keyIDs))
	for i, id := range keyIDs {
		args[i] = id
	}
	rows, err := s.db.Query(`SELECT key_id, last_used FROM key_use WHERE key_id IN (`+placeholders(len(keyIDs))+`)`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var t int64
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// Approve makes a publisher from an application in one transaction: the
// record, this master's opinion, the key, and the application's decision.
func (s *Store) Approve(a *model.Application, p *model.Publisher, o model.Opinion, k model.KeyRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO publishers (`+publisherColumns+`) VALUES (`+placeholders(8)+`)`,
		p.ID, p.Name, p.Email, p.Discord, p.Origin, p.Since, p.Created, p.Updated); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO opinions (publisher_id, source, status, quota, reason, updated)
		VALUES (?, ?, ?, ?, ?, ?)`, o.PublisherID, o.Source, o.Status, o.Quota, o.Reason, o.Updated); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO keys (`+keyColumns+`) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (key_id, source) DO UPDATE SET publisher_id = excluded.publisher_id, status = excluded.status,
		updated = excluded.updated`, k.KeyID, k.Source, k.PublisherID, k.PublicKey, k.Status, k.Updated); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE applications SET status = ?, publisher_id = ?, decided_by = ?, updated = ?
		WHERE id = ?`, model.ApplicationApproved, p.ID, a.DecidedBy, s.now(), a.ID); err != nil {
		return err
	}
	return tx.Commit()
}
