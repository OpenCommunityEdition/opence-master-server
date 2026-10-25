// Package core is the master's administration: who a key belongs to, the
// approval of applications, the moderation of publishers and keys, and the
// servers the list shows. The HTTP handlers, the admin pages and the
// command line all go through it, so each action is audited the same way.
package core

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// Protocol is the protocol version the master speaks.
const Protocol = 1

// MaximumKeys is how many active keys a publisher may hold.
const MaximumKeys = 8

// MaximumQuota is the largest quota a publisher is given.
const MaximumQuota = 1000

// Version is the program's version, set at build time.
var Version = "dev"

// Peer is another master: its URL and key.
type Peer struct {
	URL   string
	Key   ed25519.PublicKey
	KeyID string
}

// Master is the master's state and its administration.
type Master struct {
	Store      *store.Store
	Key        ed25519.PrivateKey
	KeyID      string
	KeyIDBytes [8]byte
	Config     *config.Config
	Notifier   *mail.Notifier
	Log        *slog.Logger
	Now        func() time.Time
	Peers      []Peer
	// told of applications made and decided, besides the notifier (the
	// Discord bot); nil for none
	Watcher Watcher

	// held while an application is checked and stored (Apply)
	applying sync.Mutex
	trustAll bool
	trusted  map[string]bool
	list     listCache
	profile  atomic.Pointer[Profile]
}

// Watcher is told of applications (the Discord bot).
type Watcher interface {
	// an application was made, approved or denied
	ApplicationChanged(id string)
	// an alert for the admins
	Alert(text string)
}

func (m *Master) changed(applicationID string) {
	if m.Watcher != nil {
		m.Watcher.ApplicationChanged(applicationID)
	}
}

// New makes a master.
func New(st *store.Store, key ed25519.PrivateKey, cfg *config.Config, notifier *mail.Notifier, log *slog.Logger) (*Master, error) {
	public := key.Public().(ed25519.PublicKey)
	m := &Master{
		Store: st, Key: key, KeyID: sign.KeyID(public), KeyIDBytes: sign.KeyIDBytes(public), Config: cfg,
		Notifier: notifier, Log: log, Now: time.Now, trusted: map[string]bool{},
	}
	if err := m.loadProfile(); err != nil {
		return nil, err
	}
	peers, err := ParsePeers(cfg.Peers)
	if err != nil {
		return nil, fmt.Errorf("MASTER_PEERS: %w", err)
	}
	for _, p := range peers {
		if p.KeyID != m.KeyID {
			m.Peers = append(m.Peers, p)
		}
	}
	switch trust := strings.ToLower(strings.TrimSpace(cfg.PeersTrust)); trust {
	case "", "all":
		m.trustAll = true
	case "none":
	default:
		for _, id := range strings.FieldsFunc(trust, func(r rune) bool { return r == ',' || r == ' ' }) {
			if !sign.ValidKeyID(id) {
				return nil, fmt.Errorf("MASTER_PEERS_TRUST: %q is not a key id", id)
			}
			m.trusted[id] = true
		}
	}
	return m, nil
}

// ParsePeers reads peers: a masters.txt file's path, or "<url> ed25519:<hex>"
// entries separated by commas or new lines; '#' starts a comment.
func ParsePeers(text string) ([]Peer, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	if !strings.Contains(text, " ") {
		if data, err := os.ReadFile(text); err == nil {
			text = string(data)
		}
	}
	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(text, ",", "\n")))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("%q: a peer is \"<url> ed25519:<64 hex>\"", line)
		}
		u, err := url.Parse(fields[0])
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("%q is not an http(s) URL", fields[0])
		}
		key, err := sign.ParsePublicKey(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%q: %w", fields[1], err)
		}
		peers = append(peers, Peer{URL: strings.TrimRight(fields[0], "/"), Key: key, KeyID: sign.KeyID(key)})
	}
	return peers, scanner.Err()
}

// Peer returns a configured peer by key id.
func (m *Master) Peer(keyID string) *Peer {
	for i := range m.Peers {
		if m.Peers[i].KeyID == keyID {
			return &m.Peers[i]
		}
	}
	return nil
}

// Trusted tells whether a source's opinions count: this master's own, and
// the configured peers' that MASTER_PEERS_TRUST allows.
func (m *Master) Trusted(source string) bool {
	if source == m.KeyID {
		return true
	}
	if m.Peer(source) == nil {
		return false
	}
	return m.trustAll || m.trusted[source]
}

// TrustedPeer tells whether a peer's records are imported.
func (m *Master) TrustedPeer(keyID string) bool { return keyID != m.KeyID && m.Trusted(keyID) }

func (m *Master) now() int64 { return m.Now().Unix() }

// NewID makes a record's id: a prefix and 16 base32 characters.
func NewID(prefix string) string {
	var raw [10]byte
	_, _ = rand.Read(raw[:])
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]))
}

// ---------- who a key is

// Identity is what the master knows of a key.
type Identity struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	// active or revoked; empty for a key only in an application
	KeyStatus string
	Publisher *model.Publisher
	// approved, suspended or revoked; pending or denied for an application's key
	Status   string
	StatusBy string
	Reason   string
	Quota    int
	// the newest application for the key, when it has no publisher
	Application *model.Application
}

// ErrUnknownKey is returned for a key the master has never seen.
var ErrUnknownKey = errors.New("unknown key")

// Identify returns what the master knows of a key.
func (m *Master) Identify(keyID string) (*Identity, error) {
	records, err := m.Store.KeyRecords(keyID)
	if err != nil {
		return nil, err
	}
	publisherID, publicText, keyStatus := model.EffectiveKey(records, m.Trusted)
	if publisherID != "" {
		public, err := sign.ParsePublicKey(publicText)
		if err != nil || sign.KeyID(public) != keyID {
			// (a record that came in malformed: no key a request can match)
			m.Log.Warn("a key record's public key is not its key id's", "key_id", keyID)
			return nil, ErrUnknownKey
		}
		id := &Identity{KeyID: keyID, PublicKey: public, KeyStatus: keyStatus}
		publisher, err := m.Store.Publisher(publisherID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnknownKey
		} else if err != nil {
			return nil, err
		}
		id.Publisher = publisher
		opinions, err := m.Store.Opinions(publisherID)
		if err != nil {
			return nil, err
		}
		id.Status, id.Quota, id.StatusBy = model.Effective(opinions, m.Trusted)
		for _, o := range opinions {
			if o.Source == id.StatusBy {
				id.Reason = o.Reason
			}
		}
		if id.Quota == 0 {
			id.Quota = m.Config.DefaultQuota
		}
		if id.Status == "" {
			return nil, ErrUnknownKey
		}
		return id, nil
	}
	application, err := m.Store.LatestApplicationForKey(keyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownKey
	} else if err != nil {
		return nil, err
	}
	public, err := sign.ParsePublicKey(application.PublicKey)
	if err != nil || sign.KeyID(public) != keyID {
		m.Log.Warn("an application's public key is not its key id's", "key_id", keyID)
		return nil, ErrUnknownKey
	}
	status := model.Pending
	if application.Status == model.ApplicationDenied {
		status = model.ApplicationDenied
	}
	return &Identity{KeyID: keyID, PublicKey: public, Status: status, Application: application,
		Reason: application.Reason}, nil
}

// PublisherState is a publisher's effective state.
type PublisherState struct {
	Publisher *model.Publisher
	Status    string
	StatusBy  string
	Quota     int
	Opinions  []model.Opinion
	Keys      []KeyState
}

// KeyState is a key's effective state.
type KeyState struct {
	KeyID     string
	PublicKey string
	Status    string
	Updated   int64
	LastUsed  int64
	Sources   []string
}

// State returns a publisher's effective state.
func (m *Master) State(publisherID string) (*PublisherState, error) {
	publisher, err := m.Store.Publisher(publisherID)
	if err != nil {
		return nil, err
	}
	opinions, err := m.Store.Opinions(publisherID)
	if err != nil {
		return nil, err
	}
	state := &PublisherState{Publisher: publisher, Opinions: opinions}
	state.Status, state.Quota, state.StatusBy = model.Effective(opinions, m.Trusted)
	if state.Quota == 0 {
		state.Quota = m.Config.DefaultQuota
	}
	records, err := m.Store.PublisherKeys(publisherID)
	if err != nil {
		return nil, err
	}
	byKey := map[string][]model.KeyRecord{}
	var order []string
	for _, r := range records {
		if byKey[r.KeyID] == nil {
			order = append(order, r.KeyID)
		}
		byKey[r.KeyID] = append(byKey[r.KeyID], r)
	}
	used, err := m.Store.KeyLastUsed(order)
	if err != nil {
		return nil, err
	}
	for _, id := range order {
		owner, public, status := model.EffectiveKey(byKey[id], m.Trusted)
		if owner != publisherID {
			continue
		}
		k := KeyState{KeyID: id, PublicKey: public, Status: status, LastUsed: used[id]}
		for _, r := range byKey[id] {
			k.Sources = append(k.Sources, r.Source)
			if r.Updated > k.Updated {
				k.Updated = r.Updated
			}
		}
		state.Keys = append(state.Keys, k)
	}
	return state, nil
}

// States returns every publisher's effective state.
func (m *Master) States() ([]*PublisherState, error) {
	publishers, err := m.Store.Publishers()
	if err != nil {
		return nil, err
	}
	var out []*PublisherState
	for _, p := range publishers {
		state, err := m.State(p.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Publisher.Since < out[j].Publisher.Since })
	return out, nil
}
