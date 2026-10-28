package netlist

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// The fetches' size caps.
const (
	// iptoasn's gzipped table (some 9 MB in 2026)
	MaximumCompressed = 64 << 20
	// its table uncompressed (some 30 MB)
	MaximumUncompressed = 512 << 20
	// a text list
	MaximumText = 16 << 20
)

// FetchTimeout is how long one source's fetch may take.
const FetchTimeout = 5 * time.Minute

// Source is a source of the netlist.
type Source struct {
	// "<kind> <url>": the source's key in the database
	ID   string
	Kind string
	URL  string
	// what the admin lookup says of an address the source lists
	Label string
}

// NewSource makes a source of a kind and URL.
func NewSource(kind, link string) Source {
	return Source{ID: kind + " " + link, Kind: kind, URL: link, Label: label(kind, link)}
}

// label names a source for the admin lookup: "tor exit", "vpn ASN",
// "x4bnet vpn list".
func label(kind, link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	what := ""
	for _, word := range []string{"vpn", "datacenter"} {
		if strings.Contains(strings.ToLower(u.Path), "/"+word+"/") {
			what = word
		}
	}
	owner := u.Hostname()
	if parts := strings.Split(strings.Trim(u.Path, "/"), "/"); (owner == "raw.githubusercontent.com" ||
		owner == "github.com") && len(parts) > 0 && parts[0] != "" {
		owner = strings.ToLower(parts[0])
	}
	switch kind {
	case KindTor:
		return "tor exit"
	case KindIPToASN:
		return "iptoasn"
	case KindASN:
		if what == "" {
			what = owner
		}
		return what + " ASN"
	}
	if what == "" {
		return owner + " list"
	}
	return owner + " " + what + " list"
}

// SourceState is a source and its last fetches.
type SourceState struct {
	Source
	Fetched, OK int64
	Error       string
	Entries     int
	// why the next fetch is due: the source's interval
	Interval time.Duration
}

// data is a source's last good copy, read.
type data struct {
	asns   map[uint32]bool
	table  *Table
	ranges []Range
}

func (d *data) entries() int {
	switch {
	case d.table != nil:
		return len(d.table.Rows)
	case d.asns != nil:
		return len(d.asns)
	}
	return len(d.ranges)
}

func (d *data) marshal() ([]byte, error) {
	switch {
	case d.table != nil:
		return d.table.MarshalBinary()
	case d.asns != nil:
		list := make([]uint32, 0, len(d.asns))
		for n := range d.asns {
			list = append(list, n)
		}
		return encodeASNs(list), nil
	}
	return encodeRanges(d.ranges), nil
}

func unmarshal(kind string, raw []byte) (*data, error) {
	switch kind {
	case KindIPToASN:
		t := &Table{}
		if err := t.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		return &data{table: t}, nil
	case KindASN:
		list, err := decodeASNs(raw)
		if err != nil {
			return nil, err
		}
		return &data{asns: asnSet(list)}, nil
	}
	ranges, err := decodeRanges(raw)
	return &data{ranges: ranges}, err
}

func asnSet(list []uint32) map[uint32]bool {
	set := make(map[uint32]bool, len(list))
	for _, n := range list {
		set[n] = true
	}
	return set
}

// Published is a netlist served: its body, signed.
type Published struct {
	Body []byte
	// the Signature header: "ed25519=" and the base64 of the signature
	Signature string
	Serial    uint64
	Generated int64
	Ranges    int
	Addresses uint64
	ETag      string

	gzipOnce sync.Once
	gzipped  []byte
}

// Gzipped is the body gzipped, made when first asked for.
func (p *Published) Gzipped() []byte {
	p.gzipOnce.Do(func() {
		var buffer bytes.Buffer
		w, _ := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
		_, _ = w.Write(p.Body)
		_ = w.Close()
		p.gzipped = buffer.Bytes()
	})
	return p.gzipped
}

// ETag is a body's ETag: the first 16 hexadecimal digits of its SHA-256,
// quoted.
func ETag(body []byte) string {
	digest := sha256.Sum256(body)
	return `"` + hex.EncodeToString(digest[:8]) + `"`
}

func published(p *store.PublishedNetlist) *Published {
	return &Published{Body: p.Body, Signature: p.Signature, Serial: p.Serial, Generated: p.Generated,
		Ranges: p.Ranges, Addresses: p.Addresses, ETag: ETag(p.Body)}
}

// Build is a list built but held: fewer than half the last published
// list's addresses.
type Build struct {
	Ranges    []Range
	Generated int64
	Addresses uint64
}

// Outcomes of a build.
const (
	OutcomePublished = "published"
	OutcomeUnchanged = "unchanged"
	OutcomeHeld      = "held"
	OutcomeFailed    = "failed"
)

// Result is a build's outcome.
type Result struct {
	At        int64
	Outcome   string
	Detail    string
	Ranges    int
	Addresses uint64
}

// Builder builds the netlist from its sources, in the background, and
// keeps the list served.
type Builder struct {
	Store  *store.Store
	Key    ed25519.PrivateKey
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time
	// the sources, in their order
	Sources []Source
	// how often the sources are fetched (Tor's: TorInterval)
	Interval, TorInterval time.Duration
	UserAgent             string
	// what Run calls after each build (nil: nothing)
	Built func(Result)

	building sync.Mutex
	current  atomic.Pointer[Published]
	kick     chan bool

	mu       sync.Mutex
	loaded   bool
	states   map[string]*SourceState
	data     map[string]*data
	held     *Build
	last     Result
	ranges   []Range
	running  bool
	fetching bool
}

// New makes a builder; Load reads what the database holds.
func New(st *store.Store, key ed25519.PrivateKey, client *http.Client, log *slog.Logger, sources []Source,
	interval, torInterval time.Duration, userAgent string) *Builder {
	return &Builder{Store: st, Key: key, Client: client, Log: log, Now: time.Now, Sources: sources,
		Interval: interval, TorInterval: torInterval, UserAgent: userAgent, kick: make(chan bool, 1),
		states: map[string]*SourceState{}, data: map[string]*data{}}
}

// Load reads the list served and the sources' states from the database,
// and forgets the sources no longer configured.
func (b *Builder) Load() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loaded {
		return nil
	}
	p, err := b.Store.PublishedNetlist()
	if err != nil {
		return err
	}
	if p != nil {
		b.current.Store(published(p))
		if l, err := Decode(p.Body); err == nil {
			b.ranges = l.Ranges
		}
		b.last = Result{At: p.Built, Outcome: OutcomePublished, Ranges: p.Ranges, Addresses: p.Addresses,
			Detail: fmt.Sprintf("serial %d (stored)", p.Serial)}
	}
	ids := make([]string, len(b.Sources))
	for i, s := range b.Sources {
		ids[i] = s.ID
		b.states[s.ID] = &SourceState{Source: s, Interval: b.interval(s)}
	}
	if err := b.Store.DeleteNetlistSourcesExcept(ids); err != nil {
		return err
	}
	stored, err := b.Store.NetlistSources()
	if err != nil {
		return err
	}
	for _, n := range stored {
		if state := b.states[n.ID]; state != nil {
			state.Fetched, state.OK, state.Error, state.Entries = n.Fetched, n.OK, n.Error, n.Entries
		}
	}
	b.loaded = true
	return nil
}

func (b *Builder) interval(s Source) time.Duration {
	if s.Kind == KindTor {
		return b.TorInterval
	}
	return b.Interval
}

// sourceData returns a source's last good copy, read from the database the
// first time (nil for none).
func (b *Builder) sourceData(s Source) *data {
	b.mu.Lock()
	d, ok := b.data[s.ID]
	b.mu.Unlock()
	if ok {
		return d
	}
	raw, err := b.Store.NetlistSourceData(s.ID)
	if err == nil && raw != nil {
		d, err = unmarshal(s.Kind, raw)
	}
	if err != nil {
		b.Log.Warn("netlist: a source's last good copy is unreadable", "source", s.URL, "err", err)
		d = nil
	}
	b.mu.Lock()
	if _, ok := b.data[s.ID]; !ok {
		b.data[s.ID] = d
	}
	d = b.data[s.ID]
	b.mu.Unlock()
	return d
}

// Current is the list served (nil: none yet).
func (b *Builder) Current() *Published { return b.current.Load() }

// countingReader fails past its cap.
type countingReader struct {
	r       io.Reader
	n, max  int64
	tooMany bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		c.tooMany = true
		return n, fmt.Errorf("more than %d bytes", c.max)
	}
	return n, err
}

// fetch fetches and reads one source.
func (b *Builder) fetch(ctx context.Context, s Source) (*data, error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", b.UserAgent)
	response, err := b.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	maximum := int64(MaximumText)
	if s.Kind == KindIPToASN {
		maximum = MaximumCompressed
	}
	body := &countingReader{r: response.Body, max: maximum}
	switch s.Kind {
	case KindIPToASN:
		t, err := ParseIPToASN(body, MaximumUncompressed)
		if err != nil {
			return nil, err
		}
		return &data{table: t}, nil
	case KindASN:
		list, err := ParseASNList(body)
		if err != nil {
			return nil, err
		}
		return &data{asns: asnSet(list)}, nil
	}
	ranges, err := ParseRangeList(body)
	if err != nil {
		return nil, err
	}
	return &data{ranges: ranges}, nil
}

// refresh fetches the sources given, keeping the last good copy of each one
// that fails.
func (b *Builder) refresh(ctx context.Context, sources []Source) {
	for _, s := range sources {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		d, err := b.fetch(ctx, s)
		now := b.Now().Unix()
		record := store.NetlistSource{ID: s.ID, URL: s.URL, Fetched: now}
		if err == nil {
			record.Data, err = d.marshal()
		}
		if err != nil {
			record.Error = err.Error()
			record.Data = nil
			b.Log.Warn("netlist: a source failed; its last good copy is kept", "source", s.URL, "err", err)
		} else {
			record.OK, record.Entries = now, d.entries()
			b.Log.Info("netlist: fetched a source", "source", s.URL, "entries", record.Entries,
				"took", time.Since(started).Round(time.Millisecond))
		}
		if serr := b.Store.SetNetlistSource(record); serr != nil {
			b.Log.Warn("netlist: a source's copy was not stored", "source", s.URL, "err", serr)
		}
		b.mu.Lock()
		state := b.states[s.ID]
		state.Fetched, state.Error = now, record.Error
		if err == nil {
			state.OK, state.Entries = now, record.Entries
			b.data[s.ID] = d
		}
		b.mu.Unlock()
	}
}

// Policy returns the master admin's settings' texts (the defaults for
// those not set).
func (b *Builder) Policy() (map[string]string, error) {
	stored, err := b.Store.NetlistPolicy()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, key := range PolicyKeys {
		if v, ok := stored[key]; ok {
			out[key] = v
		} else {
			out[key] = DefaultPolicy[key]
		}
	}
	return out, nil
}

// SetPolicy checks and stores the master admin's settings, writes them to
// the audit log, and builds the list again (in the background, once Run
// runs).
func (b *Builder) SetPolicy(texts map[string]string, actor string) error {
	p, err := ParsePolicy(texts)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, key := range PolicyKeys {
		values[key] = strings.TrimSpace(strings.ReplaceAll(texts[key], "\r\n", "\n"))
	}
	if err := b.Store.SetNetlistPolicy(values); err != nil {
		return err
	}
	_ = b.Store.Audit(actor, "netlist-policy", "", fmt.Sprintf("blocked: %d autonomous systems, %d ranges; "+
		"allowed: %d autonomous systems, %d ranges", len(p.ExtraASNs), len(p.Block), len(p.AllowASNs), len(p.Allow)))
	b.Kick(false)
	return nil
}

// Kick asks Run for a build (fetching every source first when fetch).
func (b *Builder) Kick(fetch bool) {
	select {
	case b.kick <- fetch:
	default:
		if fetch {
			// (a build waits already: make it a fetching one)
			select {
			case <-b.kick:
			default:
			}
			select {
			case b.kick <- true:
			default:
			}
		}
	}
}

// Rebuild asks for the sources fetched and the list built now, in the
// background, and writes it to the audit log.
func (b *Builder) Rebuild(actor string) {
	_ = b.Store.Audit(actor, "netlist-rebuild", "", "")
	b.Kick(true)
}

// compile makes the list from the sources' last good copies and the
// policy.
func (b *Builder) compile(policy Policy) ([]Range, []string) {
	var notes []string
	var table *Table
	systems := asnSet(policy.ExtraASNs)
	var ranges []Range
	for _, s := range b.Sources {
		d := b.sourceData(s)
		if d == nil {
			notes = append(notes, "no copy of "+s.URL+" yet")
			continue
		}
		switch s.Kind {
		case KindIPToASN:
			table = d.table
		case KindASN:
			for n := range d.asns {
				systems[n] = true
			}
		default:
			ranges = append(ranges, d.ranges...)
		}
	}
	if table == nil && len(systems) > 0 {
		notes = append(notes, "no iptoasn table: the autonomous systems are not expanded")
	}
	ranges = append(ranges, table.Ranges(systems)...)
	ranges = append(ranges, policy.Block...)
	var remove []Range
	for _, p := range netaddr.NotGlobal4() {
		if r, ok := PrefixRange(p); ok {
			remove = append(remove, r)
		}
	}
	remove = append(remove, policy.Allow...)
	remove = append(remove, table.Ranges(asnSet(policy.AllowASNs))...)
	return Subtract(ranges, remove), notes
}

// BuildNow fetches the sources given (all of them when all, else those
// due), builds the list, and publishes it unless it is the same as the
// list served or the shrink guard holds it.
func (b *Builder) BuildNow(ctx context.Context, all bool) (Result, error) {
	b.building.Lock()
	defer b.building.Unlock()
	if err := b.Load(); err != nil {
		return Result{}, err
	}
	var sources []Source
	if all {
		sources = b.Sources
	} else {
		sources = b.due(b.Now())
	}
	b.setFetching(true)
	b.refresh(ctx, sources)
	b.setFetching(false)
	return b.build()
}

func (b *Builder) setFetching(on bool) {
	b.mu.Lock()
	b.fetching = on
	b.mu.Unlock()
}

func (b *Builder) build() (Result, error) {
	now := b.Now()
	texts, err := b.Store.NetlistPolicy()
	if err != nil {
		return Result{}, err
	}
	policy, err := ParsePolicy(texts)
	if err != nil {
		// (stored by an older version, or by hand: the build fails rather than
		// drop the admin's ranges)
		return b.finish(Result{At: now.Unix(), Outcome: OutcomeFailed, Detail: "the settings: " + err.Error()}), nil
	}
	ranges, notes := b.compile(policy)
	result := Result{At: now.Unix(), Ranges: len(ranges), Addresses: Count(ranges), Detail: strings.Join(notes, "; ")}
	if len(ranges) == 0 {
		result.Outcome = OutcomeFailed
		result.Detail = strings.TrimPrefix(result.Detail+"; no source gave an address", "; ")
		return b.finish(result), nil
	}
	current := b.Current()
	b.mu.Lock()
	same := current != nil && Equal(ranges, b.ranges)
	b.mu.Unlock()
	switch {
	case same:
		result.Outcome = OutcomeUnchanged
		if err := b.Store.SetNetlistBuilt(now.Unix()); err != nil {
			return Result{}, err
		}
		b.mu.Lock()
		b.held = nil
		b.mu.Unlock()
	case current != nil && result.Addresses < current.Addresses/2:
		result.Outcome = OutcomeHeld
		result.Detail = strings.TrimPrefix(result.Detail+fmt.Sprintf("; %d addresses, fewer than half the %d of "+
			"serial %d: held until an admin publishes it", result.Addresses, current.Addresses, current.Serial), "; ")
		b.mu.Lock()
		b.held = &Build{Ranges: ranges, Generated: now.Unix(), Addresses: result.Addresses}
		b.mu.Unlock()
	default:
		p, err := b.publish(ranges, now.Unix())
		if err != nil {
			return Result{}, err
		}
		result.Outcome = OutcomePublished
		result.Detail = strings.TrimPrefix(result.Detail+fmt.Sprintf("; serial %d", p.Serial), "; ")
	}
	return b.finish(result), nil
}

func (b *Builder) finish(r Result) Result {
	b.mu.Lock()
	b.last = r
	b.mu.Unlock()
	level := slog.LevelInfo
	if r.Outcome == OutcomeFailed || r.Outcome == OutcomeHeld {
		level = slog.LevelWarn
	}
	b.Log.Log(context.Background(), level, "netlist: built", "outcome", r.Outcome, "ranges", r.Ranges,
		"addresses", r.Addresses, "detail", r.Detail)
	return r
}

// publish signs and stores a list as the one served, with the next serial.
func (b *Builder) publish(ranges []Range, generated int64) (*Published, error) {
	serial := uint64(1)
	if current := b.Current(); current != nil {
		serial = current.Serial + 1
	}
	body := Encode(ranges, uint64(generated), serial)
	record := &store.PublishedNetlist{Serial: serial, Generated: generated, Built: b.Now().Unix(), Body: body,
		Signature: sign.SignBody(b.Key, body), Ranges: len(ranges), Addresses: Count(ranges)}
	if err := b.Store.SetPublishedNetlist(record); err != nil {
		return nil, err
	}
	p := published(record)
	b.mu.Lock()
	b.ranges, b.held = ranges, nil
	b.current.Store(p)
	b.mu.Unlock()
	return p, nil
}

// PublishHeld publishes the build the shrink guard held, and writes it to
// the audit log.
func (b *Builder) PublishHeld(actor string) (*Published, error) {
	b.building.Lock()
	defer b.building.Unlock()
	b.mu.Lock()
	held := b.held
	b.mu.Unlock()
	if held == nil {
		return nil, errors.New("no build is held")
	}
	previous := b.Current()
	p, err := b.publish(held.Ranges, held.Generated)
	if err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("serial %d: %d ranges, %d addresses", p.Serial, p.Ranges, p.Addresses)
	if previous != nil {
		detail += fmt.Sprintf(" (serial %d had %d)", previous.Serial, previous.Addresses)
	}
	_ = b.Store.Audit(actor, "netlist-publish", "", detail)
	b.finish(Result{At: b.Now().Unix(), Outcome: OutcomePublished, Ranges: p.Ranges, Addresses: p.Addresses,
		Detail: detail + ", held, published by " + actor})
	return p, nil
}

// due is the sources whose next fetch is due: their interval after the last
// one (a failed one is tried again after TorInterval at most).
func (b *Builder) due(now time.Time) []Source {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Source
	for _, s := range b.Sources {
		if !b.next(b.states[s.ID]).After(now) {
			out = append(out, s)
		}
	}
	return out
}

func (b *Builder) next(state *SourceState) time.Time {
	if state.Fetched == 0 {
		return time.Time{}
	}
	wait := state.Interval
	if state.OK < state.Fetched && b.TorInterval < wait {
		wait = b.TorInterval
	}
	return time.Unix(state.Fetched, 0).Add(wait)
}

// Run builds the list in the background until ctx ends: at once if none is
// stored or the stored one is older than Interval, then whenever a source
// is due (Tor's every TorInterval, the others every Interval) or a build is
// asked for (Kick).
func (b *Builder) Run(ctx context.Context) {
	if err := b.Load(); err != nil {
		b.Log.Error("netlist: the database could not be read", "err", err)
		return
	}
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()
	now := b.Now()
	if p, err := b.Store.PublishedNetlist(); err == nil && p == nil {
		// (the due sources fetched, and a source fetched recently built from
		// its copy)
		b.after(ctx, false)
	} else if err == nil && now.Sub(time.Unix(p.Built, 0)) >= b.Interval {
		b.after(ctx, true)
	}
	for {
		if len(b.due(b.Now())) > 0 {
			b.after(ctx, false)
		}
		wait := time.Hour
		b.mu.Lock()
		for _, s := range b.Sources {
			if d := b.next(b.states[s.ID]).Sub(b.Now()); d < wait {
				wait = d
			}
		}
		b.mu.Unlock()
		if wait < time.Second {
			wait = time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case fetch := <-b.kick:
			timer.Stop()
			b.after(ctx, fetch)
		case <-timer.C:
		}
	}
}

// after builds (fetching all the sources when all, else those due) and
// tells Built.
func (b *Builder) after(ctx context.Context, all bool) {
	r, err := b.BuildNow(ctx, all)
	if err != nil {
		b.Log.Error("netlist: the build failed", "err", err)
		r = b.finish(Result{At: b.Now().Unix(), Outcome: OutcomeFailed, Detail: err.Error()})
	}
	if b.Built != nil {
		b.Built(r)
	}
}

// Status is what the admin page shows.
type Status struct {
	Current  *Published
	Held     *Build
	Last     Result
	Sources  []SourceState
	Running  bool
	Fetching bool
}

// Status returns the builder's state.
func (b *Builder) Status() Status {
	_ = b.Load()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := Status{Current: b.current.Load(), Held: b.held, Last: b.last, Running: b.running, Fetching: b.fetching}
	for _, source := range b.Sources {
		s.Sources = append(s.Sources, *b.states[source.ID])
	}
	return s
}

// Lookup is what the netlist says of an address.
type Lookup struct {
	Address netip.Addr
	// in the list served, and in the build held
	Listed, Held bool
	// its autonomous system in iptoasn's table (0: none known)
	ASN  uint32
	Name string
	// the sources that list it, and the admin's settings that touch it
	Labels []string
}

// Lookup says which sources list an address, and whether the list served
// holds it.
func (b *Builder) Lookup(address netip.Addr) (Lookup, error) {
	l := Lookup{Address: address.Unmap()}
	n, ok := Number(address)
	if !ok {
		return l, errors.New("the netlist is IPv4 only")
	}
	if current := b.Current(); current != nil {
		if list, err := Decode(current.Body); err == nil {
			l.Listed = Contains(list.Ranges, n)
		}
	}
	b.mu.Lock()
	held := b.held
	b.mu.Unlock()
	if held != nil {
		l.Held = Contains(held.Ranges, n)
	}
	if !netaddr.Global(l.Address) {
		l.Labels = append(l.Labels, "not a global address (never listed)")
	}
	texts, err := b.Store.NetlistPolicy()
	if err != nil {
		return l, err
	}
	policy, _ := ParsePolicy(texts)
	var table *Table
	for _, s := range b.Sources {
		if s.Kind == KindIPToASN {
			if d := b.sourceData(s); d != nil {
				table = d.table
			}
		}
	}
	l.ASN = table.Lookup(n)
	if table != nil {
		l.Name = table.Names[l.ASN]
	}
	system := func(why string) string {
		text := fmt.Sprintf("AS%d", l.ASN)
		if l.Name != "" {
			text += " " + l.Name
		}
		return text + " (" + why + ")"
	}
	for _, s := range b.Sources {
		d := b.sourceData(s)
		if d == nil {
			continue
		}
		switch s.Kind {
		case KindASN:
			if l.ASN != 0 && d.asns[l.ASN] {
				l.Labels = append(l.Labels, system(s.Label))
			}
		case KindList, KindTor:
			if Contains(d.ranges, n) {
				l.Labels = append(l.Labels, s.Label)
			}
		}
	}
	if l.ASN != 0 && asnSet(policy.ExtraASNs)[l.ASN] {
		l.Labels = append(l.Labels, system("admin ASN"))
	}
	if Contains(policy.Block, n) {
		l.Labels = append(l.Labels, "admin block")
	}
	if l.ASN != 0 && asnSet(policy.AllowASNs)[l.ASN] {
		l.Labels = append(l.Labels, system("admin allowed ASN: taken out"))
	}
	if Contains(policy.Allow, n) {
		l.Labels = append(l.Labels, "admin allow: taken out")
	}
	return l, nil
}
