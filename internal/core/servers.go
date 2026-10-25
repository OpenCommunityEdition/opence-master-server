package core

import (
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
)

const (
	// what a publisher is told to keep to
	Interval = 30 * time.Second
	// a server not published again within this is unlisted
	TTL = 90 * time.Second
	// the most entries a list holds
	MaximumEntries = 512
	// how long the servers listed are reused before they are read again
	// (the list, the list page, the publishers' pages and the metrics)
	ListCacheTime = 5 * time.Second
)

// EntryPublisher is a list entry's publisher.
type EntryPublisher struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Since string `json:"since"`
}

// Entry is a server in the list.
type Entry struct {
	ID             string         `json:"id"`
	Publisher      EntryPublisher `json:"publisher"`
	Name           string         `json:"name"`
	Map            string         `json:"map"`
	Gametype       string         `json:"gametype"`
	Variant        string         `json:"variant"`
	Players        int            `json:"players"`
	MaxPlayers     int            `json:"max_players"`
	Teams          bool           `json:"teams"`
	InProgress     bool           `json:"in_progress"`
	Password       bool           `json:"password"`
	Open           bool           `json:"open"`
	Dedicated      bool           `json:"dedicated"`
	Kind           int            `json:"kind"`
	Engine         int            `json:"engine"`
	NetworkVersion int            `json:"network_version"`
	Build          string         `json:"build"`
	Region         string         `json:"region"`
	Reachable      bool           `json:"reachable"`
	Updated        int64          `json:"updated"`
	Address        string         `json:"address,omitempty"`
	Listing        string         `json:"listing"`
}

// Filter narrows the list.
type Filter struct {
	NetworkVersion int
	Dedicated      *bool
	Region         string
	Query          string
}

// Since writes a publisher's start as the list shows it: year and month.
func Since(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01")
}

// ProbeAllows tells whether a server's probe lets it be listed.
func (m *Master) ProbeAllows(s *model.Server) bool {
	if !m.Config.Probe || s.Trusted || s.Probe == string(probe.OK) {
		return true
	}
	return m.Config.ListUnreachable && s.Probe == string(probe.Failed)
}

// Listable tells whether a server is listed, and if not, why: "" when it is.
func (m *Master) Listable(s *model.Server, state *PublisherState, now time.Time) string {
	switch {
	case !s.Live(now, TTL):
		return "expired"
	case s.Hidden:
		return "hidden"
	case state == nil || state.Status != model.Approved:
		return "publisher"
	}
	keyActive := false
	for _, k := range state.Keys {
		if k.KeyID == s.KeyID && k.Status == model.KeyActive {
			keyActive = true
		}
	}
	if !keyActive {
		return "key"
	}
	if !m.ProbeAllows(s) {
		return "probe"
	}
	return ""
}

func matches(e *Entry, f Filter) bool {
	if f.NetworkVersion != 0 && e.NetworkVersion != f.NetworkVersion {
		return false
	}
	if f.Dedicated != nil && e.Dedicated != *f.Dedicated {
		return false
	}
	if f.Region != "" && e.Region != f.Region {
		return false
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		if !strings.Contains(strings.ToLower(e.Name), q) && !strings.Contains(strings.ToLower(e.Map), q) &&
			!strings.Contains(strings.ToLower(e.Gametype), q) && !strings.Contains(strings.ToLower(e.Variant), q) {
			return false
		}
	}
	return true
}

// MakeEntry writes a server as the list has it.
func (m *Master) MakeEntry(s *model.Server, state *PublisherState) Entry {
	e := Entry{
		ID: s.ID, Publisher: EntryPublisher{ID: state.Publisher.ID, Name: state.Publisher.Name,
			Since: Since(state.Publisher.Since)},
		Name: s.Name, Map: s.Map, Gametype: s.Gametype, Variant: s.Variant, Players: s.Players,
		MaxPlayers: s.MaxPlayers, Teams: s.Teams, InProgress: s.InProgress, Password: s.Password, Open: s.Open,
		Dedicated: s.Dedicated, Kind: s.Kind, Engine: s.Engine, NetworkVersion: s.NetworkVersion, Build: s.Build,
		Region: s.Region, Reachable: s.Probe == string(probe.OK), Updated: s.Updated,
		Listing: base64.StdEncoding.EncodeToString(s.Listing),
	}
	if m.Config.ServeAddresses && s.PublishAddress && s.Declared != "" {
		e.Address = s.Declared
	}
	return e
}

// listCache is the servers listed, read at most once each ListCacheTime.
type listCache struct {
	mu         sync.Mutex
	entries    []Entry
	made       time.Time
	generation uint64
	valid      bool
}

// Snapshot returns every server listed now (unfiltered and uncut: dedicated
// servers first, then by players), read from the database at most once each
// ListCacheTime, and the snapshot's generation, which changes with it. The
// slice is shared: callers do not change it.
func (m *Master) Snapshot() ([]Entry, uint64, error) {
	now := m.Now()
	c := &m.list
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && now.Sub(c.made) < ListCacheTime && !now.Before(c.made) {
		return c.entries, c.generation, nil
	}
	entries, err := m.listed(now)
	if err != nil {
		return nil, 0, err
	}
	c.entries, c.made, c.valid = entries, now, true
	c.generation++
	return c.entries, c.generation, nil
}

// InvalidateList makes the next Snapshot read the database again (a server
// came or went, or a publisher's status changed).
func (m *Master) InvalidateList() {
	m.list.mu.Lock()
	m.list.valid = false
	m.list.mu.Unlock()
}

func (m *Master) listed(now time.Time) ([]Entry, error) {
	servers, err := m.Store.LiveServers("", now.Unix()-int64(TTL/time.Second))
	if err != nil {
		return nil, err
	}
	states := map[string]*PublisherState{}
	out := []Entry{}
	for i := range servers {
		s := &servers[i]
		if !s.Live(now, TTL) || s.Hidden {
			continue
		}
		state, seen := states[s.PublisherID]
		if !seen {
			state, _ = m.State(s.PublisherID)
			states[s.PublisherID] = state
		}
		if m.Listable(s, state, now) != "" {
			continue
		}
		out = append(out, m.MakeEntry(s, state))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Dedicated != out[j].Dedicated {
			return out[i].Dedicated
		}
		if out[i].Players != out[j].Players {
			return out[i].Players > out[j].Players
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// FilterEntries returns the entries a filter keeps, MaximumEntries at most.
func FilterEntries(entries []Entry, f Filter) []Entry {
	out := []Entry{}
	for i := range entries {
		if matches(&entries[i], f) {
			out = append(out, entries[i])
			if len(out) == MaximumEntries {
				break
			}
		}
	}
	return out
}

// Listed returns the servers the list shows, dedicated servers first, then
// by players (from the Snapshot).
func (m *Master) Listed(f Filter) ([]Entry, error) {
	entries, _, err := m.Snapshot()
	if err != nil {
		return nil, err
	}
	return FilterEntries(entries, f), nil
}

// LiveServers returns a publisher's live servers.
func (m *Master) LiveServers(publisherID string) ([]model.Server, error) {
	now := m.Now()
	servers, err := m.Store.LiveServers(publisherID, now.Unix()-int64(TTL/time.Second))
	if err != nil {
		return nil, err
	}
	var out []model.Server
	for _, s := range servers {
		if s.Live(now, TTL) {
			out = append(out, s)
		}
	}
	return out, nil
}
