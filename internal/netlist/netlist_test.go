package netlist

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

func rng(t *testing.T, text string) Range {
	t.Helper()
	r, ok, err := ParseRangeText(text)
	if err != nil || !ok {
		t.Fatalf("%q: %v", text, err)
	}
	return r
}

func TestMergeAndSubtract(t *testing.T) {
	got := Merge([]Range{rng(t, "1.2.3.0/24"), rng(t, "1.2.4.0/24"), rng(t, "1.2.3.7"), rng(t, "1.2.6.0/24"),
		rng(t, "9.9.9.9"), rng(t, "0.0.0.0-0.0.0.1")})
	want := []Range{rng(t, "0.0.0.0-0.0.0.1"), rng(t, "1.2.3.0-1.2.4.255"), rng(t, "1.2.6.0/24"), rng(t, "9.9.9.9")}
	if !Equal(got, want) {
		t.Fatalf("merged %v, want %v", got, want)
	}
	// touching ranges join: the last of one is 2 below the first of the next at least
	if got := Merge([]Range{rng(t, "1.0.0.0-1.0.0.9"), rng(t, "1.0.0.10-1.0.0.20")}); len(got) != 1 {
		t.Fatalf("touching ranges kept apart: %v", got)
	}
	if got := Merge([]Range{rng(t, "1.0.0.0-1.0.0.9"), rng(t, "1.0.0.11")}); len(got) != 2 {
		t.Fatalf("ranges a gap apart joined: %v", got)
	}
	if got := Merge([]Range{{0, 10}, {0xfffffff0, 0xffffffff}, {5, 0xffffffff}}); !Equal(got, []Range{{0, 0xffffffff}}) {
		t.Fatalf("to the end: %v", got)
	}
	left := Subtract([]Range{rng(t, "10.0.0.0-10.0.0.255"), rng(t, "20.0.0.0/24")},
		[]Range{rng(t, "10.0.0.10-10.0.0.19"), rng(t, "10.0.0.250-20.0.0.5"), rng(t, "20.0.0.255")})
	want = []Range{rng(t, "10.0.0.0-10.0.0.9"), rng(t, "10.0.0.20-10.0.0.249"), rng(t, "20.0.0.6-20.0.0.254")}
	if !Equal(left, want) {
		t.Fatalf("subtracted %v, want %v", left, want)
	}
	if got := Subtract([]Range{{0, 0xffffffff}}, []Range{{0, 0xffffffff}}); len(got) != 0 {
		t.Fatalf("everything less everything: %v", got)
	}
	if Count(want) != 10+230+249 {
		t.Fatalf("count %d", Count(want))
	}
	if !Contains(want, 0x0a000014) || Contains(want, 0x0a00000a) || Contains(want, 0x14000000) {
		t.Fatal("Contains")
	}
}

func TestEncodeDecode(t *testing.T) {
	ranges := []Range{rng(t, "1.2.3.0/24"), rng(t, "5.6.7.8"), rng(t, "45.0.0.0/12")}
	body := Encode(ranges, 1760900000, 7)
	if len(body) != 32+8*3 || string(body[:8]) != "OPCENET1" || body[8] != 1 {
		t.Fatalf("body %x", body)
	}
	l, err := Decode(body)
	if err != nil || l.Generated != 1760900000 || l.Serial != 7 || !Equal(l.Ranges, ranges) {
		t.Fatalf("decoded %+v, %v", l, err)
	}
	bad := func(name string, change func([]byte) []byte) {
		t.Helper()
		b := change(append([]byte(nil), body...))
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	bad("magic", func(b []byte) []byte { b[0] = 'X'; return b })
	bad("format", func(b []byte) []byte { b[8] = 2; return b })
	bad("reserved", func(b []byte) []byte { b[10] = 1; return b })
	bad("short", func(b []byte) []byte { return b[:len(b)-1] })
	bad("long", func(b []byte) []byte { return append(b, 0) })
	bad("backwards", func(b []byte) []byte { b[32+8+7] = 0; b[32+8+3] = 9; return b })
	bad("touching", func(b []byte) []byte {
		return Encode([]Range{rng(t, "1.0.0.0-1.0.0.9"), rng(t, "1.0.0.10")}, 1, 1)
	})
	bad("out of order", func(b []byte) []byte { return Encode([]Range{ranges[1], ranges[0]}, 1, 1) })
	if l, err := Decode(Encode(nil, 1, 1)); err != nil || len(l.Ranges) != 0 {
		t.Fatalf("an empty list: %v", err)
	}
}

func TestParseSources(t *testing.T) {
	asns, err := ParseASNList(strings.NewReader("# a comment\nAS9009 # M247, GB (NordVPN)\n\nAS13335\nas16509 # x\nnot one\nAS9009\n"))
	if err != nil || len(asns) != 3 || asns[0] != 9009 || asns[1] != 13335 || asns[2] != 16509 {
		t.Fatalf("asns %v, %v", asns, err)
	}
	if _, err := ParseASNList(strings.NewReader("<html>\n")); err == nil {
		t.Fatal("a page with no ASN taken")
	}
	ranges, err := ParseRangeList(strings.NewReader("1.2.3.0/24\n1.2.4.0/24\n2001:db8::/32\n5.6.7.8\n"))
	if err != nil || !Equal(ranges, []Range{rng(t, "1.2.3.0-1.2.4.255"), rng(t, "5.6.7.8")}) {
		t.Fatalf("ranges %v, %v", ranges, err)
	}
	if _, err := ParseRangeList(strings.NewReader("1.2.3.0/24\n<html>\n")); err == nil {
		t.Fatal("a page of something else taken")
	}
	table, err := ParseIPToASN(bytes.NewReader(gz(ip2asn)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 4 || table.Names[9009] != "M247" || table.Lookup(0x05060708) != 9009 ||
		table.Lookup(0x01010101) != 0 {
		t.Fatalf("table %+v", table)
	}
	copied := &Table{}
	raw, _ := table.MarshalBinary()
	if err := copied.UnmarshalBinary(raw); err != nil || len(copied.Rows) != 4 || copied.Names[13335] != "CLOUDFLARENET" {
		t.Fatalf("copy %+v, %v", copied, err)
	}
	if _, err := ParseIPToASN(bytes.NewReader(gz(ip2asn)), 50); err == nil {
		t.Fatal("past the uncompressed cap")
	}
	if _, err := ParseIPToASN(strings.NewReader(ip2asn), 1<<20); err == nil {
		t.Fatal("not gzip taken")
	}
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy(map[string]string{PolicyBlock: "198.51.100.0/24 # docs\n9.9.9.9, 8.8.8.0-8.8.8.9",
		PolicyAllowASNs: "AS15169\n15169"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ExtraASNs) != 1 || p.ExtraASNs[0] != 13335 || len(p.AllowASNs) != 1 || len(p.Block) != 3 {
		t.Fatalf("%+v", p)
	}
	if _, err := ParsePolicy(map[string]string{PolicyExtraASNs: ""}); err != nil {
		t.Fatal(err)
	}
	_, err = ParsePolicy(map[string]string{PolicyAllow: "1.2.3.0/24\n2001:db8::/32\nnonsense", PolicyExtraASNs: "ASX"})
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 3") ||
		!strings.Contains(err.Error(), "blocked autonomous systems") {
		t.Fatalf("errors %v", err)
	}
}

const ip2asn = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"5.6.7.0\t5.6.7.255\t9009\tGB\tM247\n" +
	"10.0.0.0\t10.0.0.255\t9009\tGB\tM247\n" +
	"7.7.7.0\t7.7.7.255\t15169\tUS\tGOOGLE\n"

func gz(text string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(text))
	w.Close()
	return b.Bytes()
}

// fake is the sources, on loopback.
type fake struct {
	mu      sync.Mutex
	files   map[string][]byte
	failing map[string]bool
	agent   string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agent = r.Header.Get("User-Agent")
	if f.failing[r.URL.Path] {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	body, ok := f.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(body)
}

func (f *fake) set(path string, body []byte, failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = body
	f.failing[path] = failing
}

type harness struct {
	t     *testing.T
	st    *store.Store
	key   ed25519.PrivateKey
	fake  *fake
	url   string
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	f := &fake{files: map[string][]byte{
		"/dc.txt":      []byte("AS9009 # M247\n"),
		"/vpn.txt":     []byte("AS15169\n"),
		"/ip2asn.gz":   gz(ip2asn),
		"/x4b-vpn.txt": []byte("20.0.0.0/16\n192.168.0.0/16\n"),
		"/tor.txt":     []byte("30.0.0.1\n30.0.0.2\n"),
	}, failing: map[string]bool{}}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := sign.NewSeed()
	return &harness{t: t, st: st, key: key, fake: f, url: server.URL, clock: time.Unix(1760900000, 0)}
}

func (h *harness) builder() *Builder {
	sources := []Source{NewSource(KindASN, h.url+"/dc.txt"), NewSource(KindASN, h.url+"/vpn.txt"),
		NewSource(KindIPToASN, h.url+"/ip2asn.gz"), NewSource(KindList, h.url+"/x4b-vpn.txt"),
		NewSource(KindTor, h.url+"/tor.txt")}
	b := New(h.st, h.key, http.DefaultClient, slog.New(slog.NewTextHandler(io.Discard, nil)), sources, 24*time.Hour,
		time.Hour, "opence-master/test")
	b.Now = func() time.Time { return h.clock }
	return b
}

func (h *harness) build(b *Builder, all bool) Result {
	h.t.Helper()
	r, err := b.BuildNow(context.Background(), all)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func TestBuilder(t *testing.T) {
	h := newHarness(t)
	b := h.builder()
	if b.Current() != nil {
		t.Fatal("a list before a build")
	}
	r := h.build(b, true)
	if r.Outcome != OutcomePublished {
		t.Fatalf("%+v", r)
	}
	if h.fake.agent != "opence-master/test" {
		t.Fatalf("user agent %q", h.fake.agent)
	}
	p := b.Current()
	l, err := Decode(p.Body)
	if err != nil {
		t.Fatal(err)
	}
	// AS9009 and AS15169 expanded (10.0.0.0/24 is not global), AS13335 the
	// admin's default, the list (less 192.168.0.0/16), the Tor exits
	want := []Range{rng(t, "1.0.0.0/24"), rng(t, "5.6.7.0/24"), rng(t, "7.7.7.0/24"), rng(t, "20.0.0.0/16"),
		rng(t, "30.0.0.1-30.0.0.2")}
	if !Equal(l.Ranges, want) || l.Serial != 1 || int64(l.Generated) != h.clock.Unix() {
		t.Fatalf("list %v serial %d", l.Ranges, l.Serial)
	}
	if !sign.VerifyBody(h.key.Public().(ed25519.PublicKey), p.Signature, p.Body) || p.ETag != ETag(p.Body) {
		t.Fatal("signature or ETag")
	}
	gunzipped, _ := gzip.NewReader(bytes.NewReader(p.Gzipped()))
	if raw, _ := io.ReadAll(gunzipped); !bytes.Equal(raw, p.Body) {
		t.Fatal("gzip")
	}

	// the same list again: nothing new published
	h.clock = h.clock.Add(time.Hour)
	if r := h.build(b, true); r.Outcome != OutcomeUnchanged || b.Current().Serial != 1 {
		t.Fatalf("%+v", r)
	}

	// the admin's settings
	if err := b.SetPolicy(map[string]string{PolicyExtraASNs: "", PolicyAllowASNs: "AS15169",
		PolicyBlock: "40.0.0.0/30\n10.1.0.0/16", PolicyAllow: "20.0.200.0/24"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPolicy(map[string]string{PolicyBlock: "nonsense"}, "admin"); err == nil {
		t.Fatal("a bad setting taken")
	}
	r = h.build(b, false)
	l, _ = Decode(b.Current().Body)
	want = []Range{rng(t, "5.6.7.0/24"), rng(t, "20.0.0.0-20.0.199.255"), rng(t, "20.0.201.0-20.0.255.255"),
		rng(t, "30.0.0.1-30.0.0.2"), rng(t, "40.0.0.0/30")}
	if r.Outcome != OutcomePublished || !Equal(l.Ranges, want) || l.Serial != 2 {
		t.Fatalf("%+v: %v", r, l.Ranges)
	}

	// the lookup
	look := func(address string) Lookup {
		l, err := b.Lookup(netip.MustParseAddr(address))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if l := look("5.6.7.8"); !l.Listed || l.ASN != 9009 || strings.Join(l.Labels, "|") != "AS9009 M247 (127.0.0.1 ASN)" {
		t.Fatalf("%+v", l)
	}
	if l := look("7.7.7.7"); l.Listed || !strings.Contains(strings.Join(l.Labels, "|"), "admin allowed ASN") {
		t.Fatalf("%+v", l)
	}
	if l := look("30.0.0.2"); !l.Listed || l.Labels[0] != "tor exit" {
		t.Fatalf("%+v", l)
	}
	if l := look("40.0.0.1"); !l.Listed || l.Labels[0] != "admin block" {
		t.Fatalf("%+v", l)
	}
	if l := look("192.168.1.1"); l.Listed || !strings.HasPrefix(l.Labels[0], "not a global") {
		t.Fatalf("%+v", l)
	}
	if l := look("20.0.200.1"); l.Listed || !strings.Contains(strings.Join(l.Labels, "|"), "admin allow") {
		t.Fatalf("%+v", l)
	}

	// a restart: the list served and the sources' copies are the database's,
	// so a failing source keeps its copy
	h.fake.set("/ip2asn.gz", nil, true)
	h.fake.set("/tor.txt", []byte("<html>"), false)
	again := h.builder()
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	if again.Current() == nil || again.Current().Serial != 2 {
		t.Fatal("the list served was not kept")
	}
	h.clock = h.clock.Add(25 * time.Hour)
	r = h.build(again, false)
	if r.Outcome != OutcomeUnchanged {
		t.Fatalf("%+v", r)
	}
	status := again.Status()
	for _, s := range status.Sources {
		failing := s.Kind == KindIPToASN || s.Kind == KindTor
		if (s.Error != "") != failing || s.Fetched != h.clock.Unix() || s.Entries == 0 {
			t.Fatalf("%+v", s)
		}
	}

	// a source shrinks the list by more than half: held until published
	h.fake.set("/dc.txt", []byte("AS1\n"), false)
	h.fake.set("/x4b-vpn.txt", []byte("20.0.0.0/30\n"), false)
	h.clock = h.clock.Add(time.Hour)
	r = h.build(again, true)
	if r.Outcome != OutcomeHeld || again.Current().Serial != 2 || again.Status().Held == nil {
		t.Fatalf("%+v", r)
	}
	if l := look("30.0.0.1"); !l.Listed {
		t.Fatal("the lookup")
	}
	p, err = again.PublishHeld("admin")
	if err != nil || p.Serial != 3 || again.Status().Held != nil {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := again.PublishHeld("admin"); err == nil {
		t.Fatal("published twice")
	}
	entries, _ := h.st.AuditActions("netlist-publish", 0, 10)
	if len(entries) != 1 || entries[0].Actor != "admin" {
		t.Fatalf("audit %+v", entries)
	}
}

// With no source at all, nothing is published (503 rather than an empty
// list).
func TestBuilderEmpty(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/dc.txt", "/vpn.txt", "/ip2asn.gz", "/x4b-vpn.txt", "/tor.txt"} {
		h.fake.set(path, nil, true)
	}
	b := h.builder()
	if err := b.SetPolicy(map[string]string{PolicyExtraASNs: ""}, "admin"); err != nil {
		t.Fatal(err)
	}
	if r := h.build(b, true); r.Outcome != OutcomeFailed || b.Current() != nil {
		t.Fatalf("%+v", r)
	}
}

// Run builds at its start and when a build is asked for.
func TestRun(t *testing.T) {
	h := newHarness(t)
	b := h.builder()
	b.Now = time.Now
	results := make(chan Result, 4)
	b.Built = func(r Result) { results <- r }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	select {
	case r := <-results:
		if r.Outcome != OutcomePublished {
			t.Fatalf("%+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no build at the start")
	}
	b.Rebuild("admin")
	select {
	case r := <-results:
		if r.Outcome != OutcomeUnchanged {
			t.Fatalf("%+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no build when asked")
	}
}

func TestLabels(t *testing.T) {
	for _, c := range []struct{ kind, url, want string }{
		{KindASN, "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt", "vpn ASN"},
		{KindASN, "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt", "datacenter ASN"},
		{KindList, "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", "x4bnet vpn list"},
		{KindList, "https://example.org/mine.txt", "example.org list"},
		{KindTor, "https://check.torproject.org/torbulkexitlist", "tor exit"},
	} {
		if got := NewSource(c.kind, c.url).Label; got != c.want {
			t.Errorf("%s: %q, want %q", c.url, got, c.want)
		}
	}
}
