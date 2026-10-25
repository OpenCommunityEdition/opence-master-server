package store

import (
	"database/sql"
	"errors"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

const serverColumns = `id, publisher_id, key_id, instance, name, map, gametype, variant, players, max_players, teams,
	in_progress, password, open, dedicated, kind, engine, network_version, build, region, tunnel_port, listing, host_key,
	sequence, listing_time, observed, declared, publish_address, probe_address, probe, reachable, probed_at, hidden,
	hidden_reason, trusted, closed, serial, created, updated, listing_changed`

func scanServer(row scanner) (*model.Server, error) {
	var v model.Server
	var teams, inProgress, password, open, dedicated, publishAddress, reachable, hidden, trusted, closed int
	err := row.Scan(&v.ID, &v.PublisherID, &v.KeyID, &v.Instance, &v.Name, &v.Map, &v.Gametype, &v.Variant,
		&v.Players, &v.MaxPlayers, &teams, &inProgress, &password, &open, &dedicated, &v.Kind, &v.Engine,
		&v.NetworkVersion, &v.Build, &v.Region, &v.TunnelPort, &v.Listing, &v.HostKey, &v.Sequence, &v.ListingTime,
		&v.Observed, &v.Declared, &publishAddress, &v.ProbeAddress, &v.Probe, &reachable, &v.ProbedAt, &hidden,
		&v.HiddenReason, &trusted, &closed, &v.Serial, &v.Created, &v.Updated, &v.ListingChanged)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	v.Teams, v.InProgress, v.Password, v.Open, v.Dedicated = teams != 0, inProgress != 0, password != 0, open != 0,
		dedicated != 0
	v.PublishAddress, v.Reachable, v.Hidden, v.Trusted, v.Closed = publishAddress != 0, reachable != 0, hidden != 0,
		trusted != 0, closed != 0
	return &v, err
}

// Server returns a server's record.
func (s *Store) Server(id string) (*model.Server, error) {
	return scanServer(s.db.QueryRow(`SELECT `+serverColumns+` FROM servers WHERE id = ?`, id))
}

func (s *Store) servers(query string, args ...any) ([]model.Server, error) {
	rows, err := s.db.Query(`SELECT `+serverColumns+` FROM servers `+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Server
	for rows.Next() {
		v, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// Servers returns the servers' records, the most recently updated first,
// limit at most (0: all).
func (s *Store) Servers(limit int) ([]model.Server, error) {
	if limit <= 0 {
		limit = -1
	}
	return s.servers(`ORDER BY updated DESC, id LIMIT ?`, limit)
}

// LiveServers returns the servers not closed and published at since or
// after, of a publisher ("" for every publisher's).
func (s *Store) LiveServers(publisherID string, since int64) ([]model.Server, error) {
	if publisherID == "" {
		return s.servers(`WHERE closed = 0 AND updated >= ? ORDER BY updated DESC, id`, since)
	}
	return s.servers(`WHERE publisher_id = ? AND closed = 0 AND updated >= ? ORDER BY updated DESC, id`,
		publisherID, since)
}

// PublisherServers returns every server record of a publisher.
func (s *Store) PublisherServers(publisherID string) ([]model.Server, error) {
	return s.servers(`WHERE publisher_id = ? ORDER BY updated DESC, id`, publisherID)
}

// CountServers counts a publisher's server records.
func (s *Store) CountServers(publisherID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM servers WHERE publisher_id = ?`, publisherID).Scan(&n)
	return n, err
}

// DropDormant deletes a publisher's records that are not live (closed, or
// not published since since) and not flagged by an admin, the oldest
// first, until keep records are left; it returns how many it deleted.
func (s *Store) DropDormant(publisherID string, since int64, keep int) (int, error) {
	result, err := s.db.Exec(`DELETE FROM servers WHERE id IN (SELECT id FROM servers WHERE publisher_id = ?
		AND (closed = 1 OR updated < ?) AND hidden = 0 AND trusted = 0 ORDER BY updated, id
		LIMIT max(0, (SELECT COUNT(*) FROM servers WHERE publisher_id = ?) - ?))`, publisherID, since,
		publisherID, keep)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	return int(n), err
}

// LiveHostKey returns the live servers (not closed, published at since or
// after) whose listing has a host key, of publishers other than one.
func (s *Store) LiveHostKey(hostKey []byte, since int64, otherThan string) ([]model.Server, error) {
	return s.servers(`WHERE host_key = ? AND closed = 0 AND updated >= ? AND publisher_id != ? ORDER BY updated DESC,
		id LIMIT 64`, hostKey, since, otherThan)
}

// PutServer stores a server's record whole.
func (s *Store) PutServer(v *model.Server) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO servers (`+serverColumns+`) VALUES (`+placeholders(40)+`)`,
		v.ID, v.PublisherID, v.KeyID, v.Instance, v.Name, v.Map, v.Gametype, v.Variant, v.Players, v.MaxPlayers,
		boolean(v.Teams), boolean(v.InProgress), boolean(v.Password), boolean(v.Open), boolean(v.Dedicated), v.Kind,
		v.Engine, v.NetworkVersion, v.Build, v.Region, v.TunnelPort, v.Listing, v.HostKey, v.Sequence, v.ListingTime,
		v.Observed, v.Declared, boolean(v.PublishAddress), v.ProbeAddress, v.Probe, boolean(v.Reachable), v.ProbedAt,
		boolean(v.Hidden), v.HiddenReason, boolean(v.Trusted), boolean(v.Closed), v.Serial, v.Created, v.Updated,
		v.ListingChanged)
	return err
}

// SetProbe records a probe's result for a server still at that address.
func (s *Store) SetProbe(id, address, probe string, reachable bool, at int64) error {
	_, err := s.db.Exec(`UPDATE servers SET probe = ?, reachable = ?, probed_at = ? WHERE id = ? AND probe_address = ?`,
		probe, boolean(reachable), at, id, address)
	return err
}

// CloseServer unlists a server.
func (s *Store) CloseServer(id string) error {
	_, err := s.db.Exec(`UPDATE servers SET closed = 1, updated = ? WHERE id = ?`, s.now(), id)
	return err
}

// SetServerFlags sets an admin's hidden and trusted flags.
func (s *Store) SetServerFlags(id string, hidden bool, reason string, trusted bool) error {
	result, err := s.db.Exec(`UPDATE servers SET hidden = ?, hidden_reason = ?, trusted = ? WHERE id = ?`,
		boolean(hidden), reason, boolean(trusted), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
