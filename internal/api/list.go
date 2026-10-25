package api

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/metrics"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/peers"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

var publisherPattern = regexp.MustCompile(`^p_[a-z0-9]{1,32}$`)

// CacheTime is how long a signed list is served again.
const CacheTime = core.ListCacheTime

// signedBody is a body with its signature headers.
type signedBody struct {
	body      []byte
	signature string
	time      int64
	etag      string
	made      time.Time

	gzipOnce sync.Once
	gzipped  []byte
}

// compressed is the body gzipped, made when first asked for.
func (b *signedBody) compressed() []byte {
	b.gzipOnce.Do(func() {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		_, _ = writer.Write(b.body)
		_ = writer.Close()
		b.gzipped = buffer.Bytes()
	})
	return b.gzipped
}

// ListResponse is the list's body.
type ListResponse struct {
	Protocol int              `json:"protocol"`
	Master   peers.MasterInfo `json:"master"`
	Servers  []core.Entry     `json:"servers"`
}

// ServerResponse is one server's body.
type ServerResponse struct {
	Protocol int              `json:"protocol"`
	Master   peers.MasterInfo `json:"master"`
	Server   core.Entry       `json:"server"`
}

func (s *Server) masterInfo(now time.Time) peers.MasterInfo {
	return peers.MasterInfo{Name: s.M.Name(), KeyID: s.M.KeyID, Time: now.Unix()}
}

// Sign makes a signed body from a value.
func (s *Server) Sign(value any, now time.Time) *signedBody {
	body, _ := json.Marshal(value)
	digest := sha256.Sum256(body)
	return &signedBody{body: body, signature: sign.SignBody(s.M.Key, body), time: now.Unix(),
		etag: `"` + hex.EncodeToString(digest[:8]) + `"`, made: now}
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") && !strings.Contains(strings.ReplaceAll(params, " ", ""), "q=0") {
			return true
		}
	}
	return false
}

// serveSigned writes a signed body: the Signature headers, the ETag (and
// 304 for a match), gzip when asked (the signature is the uncompressed
// bytes'), and CORS for browsers.
func (s *Server) serveSigned(w http.ResponseWriter, r *http.Request, b *signedBody, cache bool) {
	h := w.Header()
	h.Set("Signature", b.signature)
	h.Set("Signature-Key", s.M.KeyID)
	h.Set("Signature-Time", strconv.FormatInt(b.time, 10))
	h.Set("ETag", b.etag)
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "Signature, Signature-Key, Signature-Time, ETag")
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Type", "application/json")
	if cache {
		h.Set("Cache-Control", "public, max-age=5")
	} else {
		h.Set("Cache-Control", "no-store")
	}
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, b.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := b.body
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = b.compressed()
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// invalidate drops the servers listed and the signed lists made of them (a
// server came or went).
func (s *Server) invalidate() {
	s.M.InvalidateList()
	s.cacheMu.Lock()
	s.cache = map[string]*signedBody{}
	s.cacheMu.Unlock()
}

// listLimited answers 429 for an address past MASTER_LIST_RATE (the list,
// one server, a publisher's page, the metrics share the limit); false then.
func (s *Server) listLimited(w http.ResponseWriter, r *http.Request) bool {
	if allowed, wait := s.lists.Allow(s.Clients.Of(r).Key()); !allowed {
		s.limited(w, wait, "too many list requests from this address")
		return true
	}
	return false
}

// ParseFilter reads the list's query.
func ParseFilter(r *http.Request) (core.Filter, string, error) {
	var f core.Filter
	q := r.URL.Query()
	if v := q.Get("network_version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return f, "network_version", errors.New("network_version is a number")
		}
		f.NetworkVersion = n
	}
	if v := q.Get("dedicated"); v != "" {
		var d bool
		switch v {
		case "1", "true":
			d = true
		case "0", "false":
		default:
			return f, "dedicated", errors.New("dedicated is 1 or 0")
		}
		f.Dedicated = &d
	}
	f.Region = strings.ToLower(q.Get("region"))
	if !regionPattern.MatchString(f.Region) {
		return f, "region", errors.New("region is up to 16 of a-z, 0-9 and -")
	}
	f.Query = q.Get("q")
	if len(f.Query) > 32 || !core.Printable(f.Query) {
		return f, "q", errors.New("q is up to 32 printable characters")
	}
	return f, "", nil
}

func filterKey(f core.Filter) string {
	dedicated := "-"
	if f.Dedicated != nil {
		dedicated = strconv.FormatBool(*f.Dedicated)
	}
	return fmt.Sprintf("%d|%s|%s|%s", f.NetworkVersion, dedicated, f.Region, strings.ToLower(f.Query))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.Metrics.Add("master_list_requests_total", "")
	if s.listLimited(w, r) {
		return
	}
	f, field, err := ParseFilter(r)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "schema", err.Error(), field)
		return
	}
	// (the servers listed are read once each CacheTime; each filter's
	// signed body is made from them once per reading)
	entries, generation, err := s.M.Snapshot()
	if err != nil {
		s.internal(w, err)
		return
	}
	key := filterKey(f)
	s.cacheMu.Lock()
	if s.cacheGeneration != generation {
		s.cache, s.cacheGeneration = map[string]*signedBody{}, generation
	}
	b := s.cache[key]
	s.cacheMu.Unlock()
	if b == nil {
		now := s.M.Now()
		b = s.Sign(ListResponse{Protocol: core.Protocol, Master: s.masterInfo(now),
			Servers: core.FilterEntries(entries, f)}, now)
		s.cacheMu.Lock()
		if s.cacheGeneration == generation {
			if len(s.cache) >= 256 {
				s.cache = map[string]*signedBody{}
			}
			s.cache[key] = b
		}
		s.cacheMu.Unlock()
	}
	s.serveSigned(w, r, b, true)
}

func (s *Server) server(w http.ResponseWriter, r *http.Request) {
	if s.listLimited(w, r) {
		return
	}
	id := r.PathValue("id")
	entries, _, err := s.M.Snapshot()
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, e := range entries {
		if e.ID == id {
			now := s.M.Now()
			s.serveSigned(w, r, s.Sign(ServerResponse{Protocol: core.Protocol, Master: s.masterInfo(now), Server: e},
				now), true)
			return
		}
	}
	s.fail(w, http.StatusNotFound, "not_found", "no server "+id+" is listed", "")
}

func (s *Server) publisher(w http.ResponseWriter, r *http.Request) {
	if s.listLimited(w, r) {
		return
	}
	id := r.PathValue("id")
	if !publisherPattern.MatchString(id) {
		s.fail(w, http.StatusNotFound, "not_found", "no publisher "+id, "")
		return
	}
	state, err := s.M.State(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && state.Status == "") {
		s.fail(w, http.StatusNotFound, "not_found", "no publisher "+id, "")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	entries, _, err := s.M.Snapshot()
	if err != nil {
		s.internal(w, err)
		return
	}
	servers := 0
	for _, e := range entries {
		if e.Publisher.ID == id {
			servers++
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": state.Publisher.ID, "name": state.Publisher.Name, "since": core.Since(state.Publisher.Since),
		"status": state.Status, "servers": servers,
	})
}

// shared answers a peer master's GET /v1/publishers?since=, signed with
// that peer's master key.
func (s *Server) shared(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.protected(w, r); !ok {
		return
	}
	auth, err := sign.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "bad_signature", err.Error(), "")
		return
	}
	now := s.M.Now()
	if !auth.InWindow(now) {
		s.fail(w, http.StatusUnauthorized, "clock", "ts is more than 300 seconds from the master's clock", "")
		return
	}
	peer := s.M.Peer(auth.KeyID)
	if peer == nil {
		s.fail(w, http.StatusForbidden, "not_a_peer", "key "+auth.KeyID+" is not a peer master's", "")
		return
	}
	if !auth.Verify(peer.Key, s.M.KeyID, r.Method, requestPath(r), nil) {
		s.fail(w, http.StatusUnauthorized, "bad_signature", "the signature does not verify", "")
		return
	}
	if fresh, err := s.M.Store.UseNonce(auth.KeyID, auth.Nonce, sign.NonceWindow); err != nil {
		s.internal(w, err)
		return
	} else if !fresh {
		s.fail(w, http.StatusUnauthorized, "replay", "the nonce was used in the last 600 seconds", "")
		return
	}
	since := int64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		if since, err = strconv.ParseInt(v, 10, 64); err != nil || since < 0 {
			s.fail(w, http.StatusBadRequest, "schema", "since is a Unix time", "since")
			return
		}
	}
	records, err := peers.Records(s.M, since)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.Metrics.Add("master_peer_requests_total", "")
	b := s.Sign(peers.Response{Protocol: core.Protocol, Master: s.masterInfo(now), Publishers: records}, now)
	s.serveSigned(w, r, b, false)
}

// gauges are the metrics read from the database, made at most once each
// CacheTime.
type gauges struct {
	made                   time.Time
	reachable, unreachable float64
	publishers             map[string]float64
}

func (s *Server) readGauges(now time.Time) (*gauges, error) {
	s.gaugesMu.Lock()
	defer s.gaugesMu.Unlock()
	if s.gauges != nil && now.Sub(s.gauges.made) < CacheTime && !now.Before(s.gauges.made) {
		return s.gauges, nil
	}
	entries, _, err := s.M.Snapshot()
	if err != nil {
		return nil, err
	}
	g := &gauges{made: now, publishers: map[string]float64{model.Approved: 0, model.Suspended: 0, model.Revoked: 0}}
	for _, e := range entries {
		if e.Reachable {
			g.reachable++
		} else {
			g.unreachable++
		}
	}
	publishers, err := s.M.States()
	if err != nil {
		return nil, err
	}
	for _, p := range publishers {
		if p.Status != "" {
			g.publishers[p.Status]++
		}
	}
	pending, err := s.M.Store.CountApplications(model.ApplicationPending)
	if err != nil {
		return nil, err
	}
	g.publishers[model.Pending] = float64(pending)
	s.gauges = g
	return g, nil
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.listLimited(w, r) {
		return
	}
	g, err := s.readGauges(s.M.Now())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Header().Set("Cache-Control", "no-store")
	metrics.WriteGauge(w, "master_servers", "Servers listed now.", []metrics.Sample{
		{Labels: map[string]string{"reachable": "true"}, Value: g.reachable},
		{Labels: map[string]string{"reachable": "false"}, Value: g.unreachable},
	})
	var samples []metrics.Sample
	for _, status := range []string{model.Pending, model.Approved, model.Suspended, model.Revoked} {
		samples = append(samples, metrics.Sample{Labels: map[string]string{"status": status},
			Value: g.publishers[status]})
	}
	metrics.WriteGauge(w, "master_publishers", "Publishers by status (pending: applications).", samples)
	s.Metrics.Write(w)
	metrics.WriteGauge(w, "master_build_info", "The master's version and protocol.", []metrics.Sample{
		{Labels: map[string]string{"version": core.Version, "protocol": strconv.Itoa(core.Protocol)}, Value: 1},
	})
}
