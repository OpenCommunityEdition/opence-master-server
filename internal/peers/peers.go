// Package peers shares approvals between masters: each master serves the
// records it holds an opinion of its own on (GET /v1/publishers?since=,
// signed), and fetches its peers' on a timer. A peer's opinion is kept as
// that peer's, beside this master's own, and the most restrictive of the
// trusted opinions is the publisher's status (model.Effective).
package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// SharedKey is a key in a shared record.
type SharedKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
	Updated   int64  `json:"updated"`
}

// Shared is a publisher's record as a master shares it: its own opinion
// (status null when it vouches only for keys) and the keys it vouches for.
type Shared struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Status  *string     `json:"status"`
	Since   int64       `json:"since"`
	Updated int64       `json:"updated"`
	Origin  string      `json:"origin"`
	Quota   int         `json:"quota"`
	Keys    []SharedKey `json:"keys"`
}

// MasterInfo heads every signed body.
type MasterInfo struct {
	Name  string `json:"name"`
	KeyID string `json:"key_id"`
	Time  int64  `json:"time"`
}

// Response is GET /v1/publishers?since='s body.
type Response struct {
	Protocol   int        `json:"protocol"`
	Master     MasterInfo `json:"master"`
	Publishers []Shared   `json:"publishers"`
}

// MaximumBody is the most a peer's answer may hold.
const MaximumBody = 8 << 20

// Freshness is how old a signed body's time may be.
const Freshness = 300 * time.Second

// Overlap is how far before a peer's time the next fetch starts, so a
// record written while the last answer was made is not missed.
const Overlap = 120

var publisherID = regexp.MustCompile(`^p_[a-z0-9]{1,32}$`)

// Records returns the records this master shares, changed after since.
func Records(m *core.Master, since int64) ([]Shared, error) {
	publishers, err := m.Store.Publishers()
	if err != nil {
		return nil, err
	}
	opinions, err := m.Store.Opinions("")
	if err != nil {
		return nil, err
	}
	keys, err := m.Store.PublisherKeys("")
	if err != nil {
		return nil, err
	}
	own := map[string]model.Opinion{}
	for _, o := range opinions {
		if o.Source == m.KeyID {
			own[o.PublisherID] = o
		}
	}
	ownKeys := map[string][]model.KeyRecord{}
	for _, k := range keys {
		if k.Source == m.KeyID {
			ownKeys[k.PublisherID] = append(ownKeys[k.PublisherID], k)
		}
	}
	out := []Shared{}
	for _, p := range publishers {
		o, hasOpinion := own[p.ID]
		if !hasOpinion && len(ownKeys[p.ID]) == 0 {
			continue
		}
		record := Shared{ID: p.ID, Name: p.Name, Since: p.Since, Origin: p.Origin, Keys: []SharedKey{}}
		if hasOpinion {
			status := o.Status
			record.Status, record.Quota, record.Updated = &status, o.Quota, o.Updated
		}
		for _, k := range ownKeys[p.ID] {
			record.Keys = append(record.Keys, SharedKey{KeyID: k.KeyID, PublicKey: k.PublicKey, Status: k.Status,
				Updated: k.Updated})
			if k.Updated > record.Updated {
				record.Updated = k.Updated
			}
		}
		if record.Updated > since {
			out = append(out, record)
		}
	}
	return out, nil
}

// Apply stores a peer's records as that peer's opinions; it returns how
// many records changed something. A publisher new here is recorded as come
// from that peer, whatever origin the record claims: the claim is the
// peer's word, and the origin decides which peer may rename the publisher.
func Apply(m *core.Master, peer string, records []Shared) (int, error) {
	changed := 0
	for _, r := range records {
		if !publisherID.MatchString(r.ID) || !sign.ValidKeyID(r.Origin) {
			continue
		}
		name := listing.SanitizeString(r.Name, 32)
		existing, err := m.Store.Publisher(r.ID)
		if err != nil {
			added, err := m.Store.InsertPublisherIfAbsent(&model.Publisher{ID: r.ID, Name: name, Origin: peer,
				Since: r.Since, Created: m.Now().Unix(), Updated: r.Updated})
			if err != nil {
				return changed, err
			}
			if added {
				changed++
				_ = m.Store.Audit("peer:"+peer, "import-publisher", r.ID, fmt.Sprintf("origin claimed %s", r.Origin))
			}
		} else if existing.Origin == peer && existing.Name != name && r.Updated > existing.Updated {
			if err := m.Store.SetPublisherName(r.ID, name, r.Updated); err != nil {
				return changed, err
			}
		}
		if r.Status != nil && model.ValidStatus(*r.Status) {
			quota := r.Quota
			if quota < 0 || quota > core.MaximumQuota {
				quota = 0
			}
			did, err := m.Store.MergeOpinion(model.Opinion{PublisherID: r.ID, Source: peer, Status: *r.Status,
				Quota: quota, Updated: r.Updated})
			if err != nil {
				return changed, err
			}
			if did {
				changed++
				_ = m.Store.Audit("peer:"+peer, "import-status", r.ID, *r.Status)
			}
		}
		for _, k := range r.Keys {
			public, err := sign.ParsePublicKey(k.PublicKey)
			if err != nil || sign.KeyID(public) != k.KeyID || (k.Status != model.KeyActive && k.Status != model.KeyRevoked) {
				continue
			}
			others, err := m.Store.KeyRecords(k.KeyID)
			if err != nil {
				return changed, err
			}
			conflict := false
			for _, o := range others {
				if o.PublisherID != r.ID {
					conflict = true
				}
			}
			if conflict {
				_ = m.Store.Audit("peer:"+peer, "import-key-refused", k.KeyID,
					"the key belongs to another publisher here")
				continue
			}
			did, err := m.Store.MergeKey(model.KeyRecord{KeyID: k.KeyID, Source: peer, PublisherID: r.ID,
				PublicKey: sign.PublicKeyText(public), Status: k.Status, Updated: k.Updated})
			if err != nil {
				return changed, err
			}
			if did {
				changed++
				_ = m.Store.Audit("peer:"+peer, "import-key", k.KeyID, k.Status)
			}
		}
	}
	return changed, nil
}

// Syncer fetches the peers' records.
type Syncer struct {
	Master *core.Master
	Client *http.Client
}

// Fetch asks one peer for its records changed since a time, and checks the
// answer's signature and freshness.
func (s *Syncer) Fetch(ctx context.Context, peer core.Peer, since int64) (*Response, error) {
	u, err := url.Parse(peer.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !loopbackHost(u.Hostname()) {
		return nil, errors.New("a peer's URL is https (http only on loopback)")
	}
	path := u.Path + "/v1/publishers"
	target := peer.URL + "/v1/publishers?since=" + strconv.FormatInt(since, 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	m := s.Master
	// (signed for that peer: its key id is in the signed string)
	request.Header.Set("Authorization", sign.Authorization(m.Key, peer.KeyID, http.MethodGet, path, nil, m.Now(),
		sign.NewNonce()))
	response, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaximumBody {
		return nil, errors.New("the answer is too large")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, bytes.TrimSpace(body[:min(len(body), 300)]))
	}
	if response.Header.Get("Signature-Key") != peer.KeyID ||
		!sign.VerifyBody(peer.Key, response.Header.Get("Signature"), body) {
		return nil, errors.New("the answer's signature is not the peer's")
	}
	var r Response
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("the answer: %w", err)
	}
	if r.Protocol != core.Protocol || r.Master.KeyID != peer.KeyID {
		return nil, errors.New("the answer is not this peer's protocol 1")
	}
	age := m.Now().Unix() - r.Master.Time
	if age > int64(Freshness/time.Second) || age < -int64(Freshness/time.Second) {
		return nil, fmt.Errorf("the answer's time is %d seconds from this master's clock", age)
	}
	return &r, nil
}

func loopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		(len(host) > 4 && host[:4] == "127.")
}

// SyncOnce fetches and applies every trusted peer's records.
func (s *Syncer) SyncOnce(ctx context.Context) {
	m := s.Master
	for _, peer := range m.Peers {
		if !m.TrustedPeer(peer.KeyID) {
			continue
		}
		state, err := m.Store.Peer(peer.KeyID)
		if err != nil {
			m.Log.Warn("peers: state", "err", err)
			continue
		}
		state.URL = peer.URL
		fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		r, err := s.Fetch(fetchCtx, peer, state.Since)
		cancel()
		if err != nil {
			state.LastError = err.Error()
			m.Log.Warn("peers: fetch failed", "peer", peer.URL, "err", err)
			_ = m.Store.SetPeer(state)
			continue
		}
		n, err := Apply(m, peer.KeyID, r.Publishers)
		if err != nil {
			state.LastError = err.Error()
			_ = m.Store.SetPeer(state)
			continue
		}
		if n > 0 {
			m.Log.Info("peers: imported", "peer", peer.URL, "changes", n)
			m.InvalidateList()
		}
		state.Since = max(0, r.Master.Time-Overlap)
		state.LastOK, state.LastError = m.Now().Unix(), ""
		_ = m.Store.SetPeer(state)
	}
}

// Run synchronises every interval until the context ends.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	s.SyncOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SyncOnce(ctx)
		}
	}
}
