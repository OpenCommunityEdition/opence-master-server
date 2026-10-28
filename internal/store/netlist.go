package store

import (
	"database/sql"
	"errors"
)

// NetlistSource is a netlist source's state and its last good copy.
type NetlistSource struct {
	// the source's kind and URL, "<kind> <url>"
	ID  string
	URL string
	// the last fetch, and the last that succeeded
	Fetched int64
	OK      int64
	Error   string
	// the entries of the last good copy (ranges, rows or systems)
	Entries int
	// the last good copy (the netlist package's form); not read by
	// NetlistSources
	Data []byte
}

// NetlistSources returns every source's state, without its copy.
func (s *Store) NetlistSources() ([]NetlistSource, error) {
	rows, err := s.db.Query(`SELECT id, url, fetched, ok, error, entries FROM netlist_sources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetlistSource
	for rows.Next() {
		var n NetlistSource
		if err := rows.Scan(&n.ID, &n.URL, &n.Fetched, &n.OK, &n.Error, &n.Entries); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NetlistSourceData returns a source's last good copy (nil for none).
func (s *Store) NetlistSourceData(id string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM netlist_sources WHERE id = ?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return data, err
}

// SetNetlistSource stores a fetch's outcome: with data (a good copy) it
// replaces the copy; without, the copy is kept.
func (s *Store) SetNetlistSource(n NetlistSource) error {
	if n.Data != nil {
		_, err := s.db.Exec(`INSERT INTO netlist_sources (id, url, fetched, ok, error, entries, data)
			VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET url = excluded.url, fetched = excluded.fetched,
			ok = excluded.ok, error = excluded.error, entries = excluded.entries, data = excluded.data`,
			n.ID, n.URL, n.Fetched, n.OK, n.Error, n.Entries, n.Data)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO netlist_sources (id, url, fetched, ok, error, entries, data)
		VALUES (?, ?, ?, 0, ?, 0, NULL) ON CONFLICT (id) DO UPDATE SET url = excluded.url, fetched = excluded.fetched,
		error = excluded.error`, n.ID, n.URL, n.Fetched, n.Error)
	return err
}

// DeleteNetlistSourcesExcept drops the sources no longer configured.
func (s *Store) DeleteNetlistSourcesExcept(ids []string) error {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	query := `DELETE FROM netlist_sources`
	if len(ids) > 0 {
		query += ` WHERE id NOT IN (` + placeholders(len(ids)) + `)`
	}
	_, err := s.db.Exec(query, args...)
	return err
}

// PublishedNetlist is the netlist served: its body and signature.
type PublishedNetlist struct {
	Serial    uint64
	Generated int64
	// the last build, which published nothing when the list was the same
	Built     int64
	Body      []byte
	Signature string
	Ranges    int
	Addresses uint64
}

// PublishedNetlist returns the netlist served (nil for none yet).
func (s *Store) PublishedNetlist() (*PublishedNetlist, error) {
	var p PublishedNetlist
	var serial, addresses int64
	err := s.db.QueryRow(`SELECT serial, generated, built, body, signature, ranges, addresses FROM netlist_published
		WHERE id = 1`).Scan(&serial, &p.Generated, &p.Built, &p.Body, &p.Signature, &p.Ranges, &addresses)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	p.Serial, p.Addresses = uint64(serial), uint64(addresses)
	return &p, nil
}

// SetPublishedNetlist stores the netlist served.
func (s *Store) SetPublishedNetlist(p *PublishedNetlist) error {
	_, err := s.db.Exec(`INSERT INTO netlist_published (id, serial, generated, built, body, signature, ranges, addresses)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET serial = excluded.serial,
		generated = excluded.generated, built = excluded.built, body = excluded.body, signature = excluded.signature,
		ranges = excluded.ranges, addresses = excluded.addresses`,
		int64(p.Serial), p.Generated, p.Built, p.Body, p.Signature, p.Ranges, int64(p.Addresses))
	return err
}

// SetNetlistBuilt records a build that published nothing new.
func (s *Store) SetNetlistBuilt(built int64) error {
	_, err := s.db.Exec(`UPDATE netlist_published SET built = ? WHERE id = 1`, built)
	return err
}

// NetlistPolicy returns the master admin's netlist settings (the ones set:
// an empty value is a setting too, unlike Setting's).
func (s *Store) NetlistPolicy() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k, v FROM netlist_policy`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetNetlistPolicy stores the master admin's netlist settings.
func (s *Store) SetNetlistPolicy(values map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err := tx.Exec(`INSERT INTO netlist_policy (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
			k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
