package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/admin"
	"github.com/OpenCommunityEdition/opence-master-server/internal/api"
	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/metrics"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/peers"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

// clock is a settable time for a master.
type clock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

type harness struct {
	t      *testing.T
	m      *core.Master
	api    *api.Server
	server *httptest.Server
	clock  *clock
	mux    *http.ServeMux
	cancel context.CancelFunc
}

func defaults(t *testing.T) *config.Config {
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	values := config.Flags(set)
	for _, o := range config.Options {
		value := o.Default
		*values[o.Env] = value
	}
	cfg, err := config.Load(values)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name, cfg.Contact = "Test master", "ops@example.org"
	cfg.AdminToken = strings.Repeat("t", 40)
	cfg.ApplicationsPerHour, cfg.ApplicationsPerKey = 1000, 1000
	return cfg
}

func newHarness(t *testing.T, change func(*config.Config)) *harness {
	t.Helper()
	cfg := defaults(t)
	if change != nil {
		change(cfg)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := sign.NewSeed()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	notifier := &mail.Notifier{Log: log, Client: http.DefaultClient, Sync: true}
	m, err := core.New(st, key, cfg, notifier, log)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{}
	m.Now = c.Now
	st.Now = c.Now
	clients := &httpx.Clients{}
	proxies, _ := cfg.Proxies()
	clients.Proxies = proxies
	ctx, cancel := context.WithCancel(context.Background())
	var prober *probe.Prober
	if cfg.Probe {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		prober = probe.New(conn, m.KeyIDBytes, probe.NewSeeds(time.Hour, c.Now()), c.Now, log)
		go prober.Run(ctx)
	}
	s := api.New(m, prober, metrics.New(), clients)
	mux := http.NewServeMux()
	s.Routes(mux)
	pages, err := web.New(m, clients)
	if err != nil {
		t.Fatal(err)
	}
	pages.Routes(mux)
	adminPages, err := admin.New(m, clients)
	if err != nil {
		t.Fatal(err)
	}
	adminPages.Routes(mux)
	h := &harness{t: t, m: m, api: s, server: httptest.NewServer(mux), clock: c, mux: mux, cancel: cancel}
	t.Cleanup(func() {
		h.server.Close()
		cancel()
		st.Close()
	})
	return h
}

// publisher is a key and its approval.
type publisher struct {
	key ed25519.PrivateKey
	id  string
}

// proof is a proof of key for an application.
func (h *harness) proof(key ed25519.PrivateKey) *core.Proof {
	nonce := h.m.ProofNonce("")
	return &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}
}

func (h *harness) applyKey(key ed25519.PrivateKey) string {
	a, err := h.m.Apply(core.ApplicationInput{Name: "Operator", Servers: 2,
		PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey)), Proof: h.proof(key)}, "test")
	if err != nil {
		h.t.Fatal(err)
	}
	return a.ID
}

func (h *harness) approved(quota int) publisher {
	key, _ := sign.NewSeed()
	p, err := h.m.Approve(h.applyKey(key), quota, "test")
	if err != nil {
		h.t.Fatal(err)
	}
	return publisher{key: key, id: p.ID}
}

var hostKey, _ = sign.NewSeed()

func (h *harness) listing(players int, flags int) []byte {
	return listing.Make(hostKey, listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen | flags, Sequence: 1,
		Time: uint32(h.clock.Now().Unix()), Players: players, MaxPlayers: 16, Engine: 1, Name: "Test server",
		Map: "bloodgulch", Gametype: "CTF"})
}

func (h *harness) do(method, path string, body []byte, auth string) (int, http.Header, []byte) {
	h.t.Helper()
	headers := map[string]string{}
	if auth != "" {
		headers["Authorization"] = auth
	}
	return h.doWith(method, path, body, headers)
}

func (h *harness) doWith(method, path string, body []byte, headers map[string]string) (int, http.Header, []byte) {
	h.t.Helper()
	request, _ := http.NewRequest(method, h.server.URL+path, bytes.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, data
}

func (h *harness) signed(key ed25519.PrivateKey, method, path string, body []byte) (int, map[string]any) {
	h.t.Helper()
	signedPath := strings.SplitN(path, "?", 2)[0]
	status, _, data := h.do(method, path, body, sign.Authorization(key, h.m.KeyID, method, signedPath, body, h.clock.Now(),
		sign.NewNonce()))
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return status, out
}

func publishBody(instance string, listingBytes []byte, port int, extra map[string]any) []byte {
	body := map[string]any{"protocol": 1, "instance": instance, "tunnel_port": port, "dedicated": true,
		"build": "test", "region": "eu", "serial": 1}
	if listingBytes != nil {
		body["listing"] = base64.StdEncoding.EncodeToString(listingBytes)
	}
	for k, v := range extra {
		body[k] = v
	}
	data, _ := json.Marshal(body)
	return data
}

func (h *harness) publish(key ed25519.PrivateKey, instance string, body []byte) (int, map[string]any) {
	id := sign.ServerID(sign.KeyID(key.Public().(ed25519.PublicKey)), instance)
	return h.signed(key, "PUT", "/v1/servers/"+id, body)
}

func code(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return ""
}

// answerer answers probes as a server's tunnel socket would.
func answerer(t *testing.T, key ed25519.PrivateKey) int {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 64)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if id, nonce, err := probe.ParseProbe(buffer[:n]); err == nil {
				conn.WriteToUDPAddrPort(probe.Answer(key, id, nonce), from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func (h *harness) list(query string) (map[string]any, http.Header, []byte) {
	h.t.Helper()
	status, header, data := h.do("GET", "/v1/servers"+query, nil, "")
	if status != 200 {
		h.t.Fatalf("list: %d %s", status, data)
	}
	if !sign.VerifyBody(h.m.Key.Public().(ed25519.PublicKey), header.Get("Signature"), data) {
		h.t.Fatal("the list's signature does not verify")
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out, header, data
}

func TestPublishFlow(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.PublishInterval = time.Second })
	key, _ := sign.NewSeed()
	port := answerer(t, key)
	listingBytes := h.listing(5, listing.FlagTeams)

	if status, out := h.publish(key, "main", publishBody("main", listingBytes, port, nil)); status != 403 ||
		code(out) != "unknown_key" {
		t.Fatalf("unknown key: %d %v", status, out)
	}
	applicationID := h.applyKey(key)
	if status, out := h.publish(key, "main", publishBody("main", listingBytes, port, nil)); status != 403 ||
		code(out) != "publisher_pending" {
		t.Fatalf("pending: %d %v", status, out)
	}
	if _, err := h.m.Approve(applicationID, 0, "test"); err != nil {
		t.Fatal(err)
	}
	status, out := h.publish(key, "main", publishBody("main", listingBytes, port, map[string]any{"players": 9}))
	if status != 202 || out["probe"] != "pending" || out["listed"] != false {
		t.Fatalf("first publish: %d %v", status, out)
	}
	if warnings, _ := out["warnings"].([]any); len(warnings) != 1 || !strings.Contains(warnings[0].(string), "players") {
		t.Fatalf("no warning for a contradicted player count: %v", out["warnings"])
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.clock.Add(time.Second)
		status, out = h.publish(key, "main", publishBody("main", listingBytes, port, nil))
		if status == 200 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if status != 200 || out["listed"] != true || out["probe"] != "ok" || out["reachable"] != true ||
		out["observed_address"] != "127.0.0.1" || out["interval"] != 30.0 || out["ttl"] != 90.0 {
		t.Fatalf("listed publish: %d %v", status, out)
	}
	body, header, raw := h.list("?network_version=38&dedicated=1")
	servers := body["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("list: %s", raw)
	}
	entry := servers[0].(map[string]any)
	if entry["listing"] != base64.StdEncoding.EncodeToString(listingBytes) || entry["players"] != 5.0 ||
		entry["teams"] != true || entry["dedicated"] != true || entry["network_version"] != 38.0 ||
		entry["region"] != "eu" || entry["reachable"] != true || entry["publisher"].(map[string]any)["name"] != "Operator" {
		t.Fatalf("entry %v", entry)
	}
	if _, ok := entry["address"]; ok {
		t.Fatal("an address was served")
	}
	digest := sha256.Sum256(raw)
	if header.Get("ETag") != `"`+hex.EncodeToString(digest[:8])+`"` || header.Get("Cache-Control") != "public, max-age=5" ||
		header.Get("Access-Control-Allow-Origin") != "*" || header.Get("Signature-Key") != h.m.KeyID ||
		header.Get("Signature-Time") != strconv.FormatInt(int64(body["master"].(map[string]any)["time"].(float64)), 10) {
		t.Fatalf("headers %v", header)
	}
	if list, _, _ := h.list("?network_version=37"); len(list["servers"].([]any)) != 0 {
		t.Fatal("another network version's filter lists it")
	}
	// the ETag gives 304; gzip is the same bytes, signed uncompressed
	request, _ := http.NewRequest("GET", h.server.URL+"/v1/servers?network_version=38&dedicated=1", nil)
	request.Header.Set("If-None-Match", header.Get("ETag"))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil || response.StatusCode != 304 {
		t.Fatalf("If-None-Match: %v %v", err, response.StatusCode)
	}
	request, _ = http.NewRequest("GET", h.server.URL+"/v1/servers?network_version=38&dedicated=1", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response, err = http.DefaultTransport.RoundTrip(request)
	if err != nil || response.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip: %v %v", err, response.Header)
	}
	reader, _ := gzip.NewReader(response.Body)
	unzipped, _ := io.ReadAll(reader)
	response.Body.Close()
	if !bytes.Equal(unzipped, raw) {
		t.Fatal("gzip body differs")
	}
	// one server, signed; the publisher's profile; the publisher's own record
	id := sign.ServerID(sign.KeyID(key.Public().(ed25519.PublicKey)), "main")
	if status, header, data := h.do("GET", "/v1/servers/"+id, nil, ""); status != 200 ||
		!sign.VerifyBody(h.m.Key.Public().(ed25519.PublicKey), header.Get("Signature"), data) {
		t.Fatalf("one server: %d", status)
	}
	if status, me := h.signed(key, "GET", "/v1/me", nil); status != 200 ||
		len(me["publisher"].(map[string]any)["servers"].([]any)) != 1 {
		t.Fatalf("me: %d %v", status, me)
	}
	// closing unlists at once
	h.clock.Add(time.Second)
	closed := h.listing(0, listing.FlagClosed)
	if status, out := h.publish(key, "main", publishBody("main", closed, port, map[string]any{"closed": true})); status != 200 ||
		out["closed"] != true {
		t.Fatalf("close: %d %v", status, out)
	}
	if list, _, _ := h.list("?network_version=38&dedicated=1"); len(list["servers"].([]any)) != 0 {
		t.Fatal("a closed server is listed")
	}
}

func TestClockReplayAndSignature(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	p := h.approved(4)
	body := publishBody("main", h.listing(1, 0), 2302, nil)
	id := sign.ServerID(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "main")
	path := "/v1/servers/" + id

	stale := sign.Authorization(p.key, h.m.KeyID, "PUT", path, body, h.clock.Now().Add(-301*time.Second), sign.NewNonce())
	status, _, data := h.do("PUT", path, body, stale)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if status != 401 || code(out) != "clock" || out["master_time"] == nil {
		t.Fatalf("stale ts: %d %s", status, data)
	}
	header := sign.Authorization(p.key, h.m.KeyID, "PUT", path, body, h.clock.Now(), sign.NewNonce())
	if status, _, data := h.do("PUT", path, body, header); status != 200 {
		t.Fatalf("publish: %d %s", status, data)
	}
	h.clock.Add(10 * time.Second)
	status, _, data = h.do("PUT", path, body, header)
	_ = json.Unmarshal(data, &out)
	if status != 401 || code(out) != "replay" {
		t.Fatalf("replay: %d %s", status, data)
	}
	auth, _ := sign.ParseAuthorization(sign.Authorization(p.key, h.m.KeyID, "PUT", path, body, h.clock.Now(), sign.NewNonce()))
	auth.Signature[0] ^= 1
	bad := sign.Scheme + " keyid=" + auth.KeyID + ", ts=" + auth.TS + ", nonce=" + auth.Nonce + ", sig=" +
		base64.StdEncoding.EncodeToString(auth.Signature)
	status, _, data = h.do("PUT", path, body, bad)
	_ = json.Unmarshal(data, &out)
	if status != 401 || code(out) != "bad_signature" {
		t.Fatalf("bad signature: %d %s", status, data)
	}
	// a signature of another body
	other := sign.Authorization(p.key, h.m.KeyID, "PUT", path, []byte("{}"), h.clock.Now(), sign.NewNonce())
	if status, _, _ := h.do("PUT", path, body, other); status != 401 {
		t.Fatalf("another body's signature: %d", status)
	}
	if status, _, _ := h.do("PUT", path, body, ""); status != 401 {
		t.Fatalf("no signature: %d", status)
	}
}

func TestSchema(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.PublishInterval = 0 })
	p := h.approved(4)
	good := h.listing(1, 0)
	forged := append([]byte(nil), good...)
	forged[len(forged)-1] ^= 1
	old := listing.Make(hostKey, listing.Fields{NetworkVersion: 38, Flags: 1, Time: uint32(h.clock.Now().Unix() - 7200),
		Name: "x", Map: "y", Gametype: "z"})
	for _, c := range []struct {
		name, field, code string
		body              []byte
		status            int
	}{
		{"not json", "", "schema", []byte("{"), 400},
		{"protocol", "protocol", "schema", publishBody("main", good, 2302, map[string]any{"protocol": 2}), 400},
		{"instance", "instance", "schema", publishBody("Main!", good, 2302, nil), 400},
		{"tunnel port type", "tunnel_port", "schema", publishBody("main", good, 0, map[string]any{"tunnel_port": "2302"}), 400},
		{"tunnel port range", "tunnel_port", "schema", publishBody("main", good, 70000, nil), 400},
		{"no listing", "listing", "schema", publishBody("main", nil, 2302, nil), 400},
		{"listing base64", "listing", "schema", publishBody("main", nil, 2302, map[string]any{"listing": "@@"}), 400},
		{"forged listing", "listing", "listing", publishBody("main", forged, 2302, nil), 400},
		{"old listing", "listing", "listing", publishBody("main", old, 2302, nil), 400},
		{"region", "region", "schema", publishBody("main", good, 2302, map[string]any{"region": "EU WEST!"}), 400},
		{"address", "address", "schema", publishBody("main", good, 2302, map[string]any{"address": "example.org:2302"}), 400},
		{"serial", "serial", "schema", publishBody("main", good, 2302, map[string]any{"serial": -1}), 400},
		{"closed type", "closed", "schema", publishBody("main", good, 2302, map[string]any{"closed": "yes"}), 400},
		{"too large", "", "too_large", publishBody("main", good, 2302, map[string]any{"note": strings.Repeat("x", 17000)}), 413},
	} {
		status, out := h.publish(p.key, "main", c.body)
		field := ""
		if e, ok := out["error"].(map[string]any); ok {
			field, _ = e["field"].(string)
		}
		if status != c.status || code(out) != c.code || field != c.field {
			t.Errorf("%s: %d %v", c.name, status, out)
		}
	}
	// the server id must be the key's and the instance's
	status, out := h.signed(p.key, "PUT", "/v1/servers/0123456789abcdef", publishBody("main", good, 2302, nil))
	if status != 400 || code(out) != "server_id" {
		t.Fatalf("server id: %d %v", status, out)
	}
	// unknown fields are ignored
	if status, out := h.publish(p.key, "main", publishBody("main", good, 2302, map[string]any{"future": 1})); status != 200 {
		t.Fatalf("unknown field: %d %v", status, out)
	}
}

func TestQuotaInstanceAndKeys(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	p := h.approved(1)
	if status, out := h.publish(p.key, "one", publishBody("one", h.listing(1, 0), 2302, nil)); status != 200 {
		t.Fatalf("first: %d %v", status, out)
	}
	if status, out := h.publish(p.key, "two", publishBody("two", h.listing(1, 0), 2303, nil)); status != 403 ||
		code(out) != "quota_exceeded" {
		t.Fatalf("over quota: %d %v", status, out)
	}
	// a second key, added by the first
	second, _ := sign.NewSeed()
	body, _ := json.Marshal(map[string]string{"public_key": sign.PublicKeyText(second.Public().(ed25519.PublicKey))})
	if status, out := h.signed(p.key, "POST", "/v1/keys", body); status != 201 || out["status"] != "active" {
		t.Fatalf("add key: %d %v", status, out)
	}
	if status, out := h.signed(p.key, "POST", "/v1/keys", body); status != 409 || code(out) != "key_exists" {
		t.Fatalf("add key twice: %d %v", status, out)
	}
	if err := h.m.SetQuota(p.id, 3, "test"); err != nil {
		t.Fatal(err)
	}
	if status, out := h.publish(second, "one", publishBody("one", h.listing(1, 0), 2304, nil)); status != 403 ||
		code(out) != "instance_taken" {
		t.Fatalf("instance taken: %d %v", status, out)
	}
	if status, out := h.publish(second, "two", publishBody("two", h.listing(1, 0), 2304, nil)); status != 200 {
		t.Fatalf("second key: %d %v", status, out)
	}
	// a revoked key: refused at once, and its server unlisted
	if err := h.m.RevokeKey(sign.KeyID(second.Public().(ed25519.PublicKey)), "test", "test"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(6 * time.Second)
	if status, out := h.publish(second, "two", publishBody("two", h.listing(1, 0), 2304, nil)); status != 403 ||
		code(out) != "key_revoked" {
		t.Fatalf("revoked key: %d %v", status, out)
	}
	list, _, _ := h.list("")
	if n := len(list["servers"].([]any)); n != 1 {
		t.Fatalf("%d listed after a key's revocation", n)
	}
	// suspended: refused, unlisted; resumed: listed again
	if err := h.m.SetStatus(p.id, "suspended", "test", "test"); err != nil {
		t.Fatal(err)
	}
	if status, out := h.publish(p.key, "one", publishBody("one", h.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "publisher_suspended" {
		t.Fatalf("suspended: %d %v", status, out)
	}
	h.clock.Add(6 * time.Second)
	if list, _, _ := h.list(""); len(list["servers"].([]any)) != 0 {
		t.Fatal("a suspended publisher's server is listed")
	}
	if err := h.m.SetStatus(p.id, "approved", "", "test"); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.publish(p.key, "one", publishBody("one", h.listing(1, 0), 2302, nil)); status != 200 {
		t.Fatalf("resumed: %d", status)
	}
	if err := h.m.SetStatus(p.id, "revoked", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := h.m.SetStatus(p.id, "approved", "", "test"); err == nil {
		t.Fatal("a revoked publisher resumed")
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.ListPerMinute = 3 })
	p := h.approved(4)
	for i := 0; i < 2; i++ {
		if status, out := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), 2302, nil)); status != 200 {
			t.Fatalf("publish %d: %d %v", i, status, out)
		}
	}
	status, header, data := h.do("PUT", "/v1/servers/"+sign.ServerID(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "main"),
		publishBody("main", h.listing(1, 0), 2302, nil), "")
	_ = header
	_ = data
	if status != 401 {
		t.Fatalf("unsigned: %d", status)
	}
	signedPath := "/v1/servers/" + sign.ServerID(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "main")
	body := publishBody("main", h.listing(1, 0), 2302, nil)
	status, header, _ = h.do("PUT", signedPath, body, sign.Authorization(p.key, h.m.KeyID, "PUT", signedPath, body, h.clock.Now(),
		sign.NewNonce()))
	if status != 429 || header.Get("Retry-After") == "" {
		t.Fatalf("third publish: %d %v", status, header)
	}
	h.clock.Add(5 * time.Second)
	if status, _ := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), 2302, nil)); status != 200 {
		t.Fatalf("after the interval: %d", status)
	}
	for i := 0; i < 3; i++ {
		h.list("")
	}
	if status, header, _ := h.do("GET", "/v1/servers", nil, ""); status != 429 || header.Get("Retry-After") == "" {
		t.Fatalf("fourth list: %d", status)
	}
}

func TestTLSRequired(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.TrustedProxies = "10.0.0.1" })
	p := h.approved(4)
	body := publishBody("main", h.listing(1, 0), 2302, nil)
	path := "/v1/servers/" + sign.ServerID(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "main")
	send := func(remote, proto string) (int, map[string]any) {
		request := httptest.NewRequest("PUT", path, bytes.NewReader(body))
		request.RemoteAddr = remote
		request.Header.Set("Authorization", sign.Authorization(p.key, h.m.KeyID, "PUT", path, body, h.clock.Now(), sign.NewNonce()))
		if proto != "" {
			request.Header.Set("X-Forwarded-Proto", proto)
			request.Header.Set("X-Forwarded-For", "198.51.100.7")
		}
		recorder := httptest.NewRecorder()
		h.mux.ServeHTTP(recorder, request)
		var out map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &out)
		return recorder.Code, out
	}
	if status, out := send("203.0.113.9:5000", ""); status != 403 || code(out) != "tls_required" {
		t.Fatalf("plain HTTP: %d %v", status, out)
	}
	// a header from anyone but the trusted proxy is not believed
	if status, out := send("203.0.113.9:5000", "https"); status != 403 || code(out) != "tls_required" {
		t.Fatalf("untrusted X-Forwarded-Proto: %d %v", status, out)
	}
	if status, out := send("10.0.0.1:5000", "http"); status != 403 || code(out) != "tls_required" {
		t.Fatalf("proxy over http: %d %v", status, out)
	}
	status, out := send("10.0.0.1:5000", "https")
	if status != 200 || out["observed_address"] != "198.51.100.7" {
		t.Fatalf("through the proxy: %d %v", status, out)
	}
	// the list needs no TLS
	request := httptest.NewRequest("GET", "/v1/servers", nil)
	request.RemoteAddr = "203.0.113.9:5000"
	recorder := httptest.NewRecorder()
	h.mux.ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("list over plain HTTP: %d", recorder.Code)
	}
}

func TestProbePolicies(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.ListUnreachable = true })
	p := h.approved(4)
	silent, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := silent.LocalAddr().(*net.UDPAddr).Port
	silent.Close()
	if status, out := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), port, nil)); status != 202 {
		t.Fatalf("first: %d %v", status, out)
	}
	time.Sleep(6500 * time.Millisecond)
	h.clock.Add(5 * time.Second)
	status, out := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), port, nil))
	if status != 200 || out["probe"] != "failed" || out["listed"] != true || out["reachable"] != false ||
		!strings.Contains(out["probe_address"].(string), strconv.Itoa(port)) {
		t.Fatalf("failed probe, listed as unreachable: %d %v", status, out)
	}
	list, _, _ := h.list("")
	if e := list["servers"].([]any)[0].(map[string]any); e["reachable"] != false {
		t.Fatal(e)
	}
	// hidden: not listed, the operator told why; trusted: listed without a probe
	id := sign.ServerID(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "main")
	if err := h.m.SetServerFlags(id, true, "rename the server", false, "test"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(5 * time.Second)
	status, out = h.publish(p.key, "main", publishBody("main", h.listing(1, 0), port, nil))
	if status != 200 || out["listed"] != false || out["hidden"] != true || out["reason"] != "rename the server" {
		t.Fatalf("hidden: %d %v", status, out)
	}
	h2 := newHarness(t, nil)
	p2 := h2.approved(4)
	h2.publish(p2.key, "main", publishBody("main", h2.listing(1, 0), port, nil))
	id2 := sign.ServerID(sign.KeyID(p2.key.Public().(ed25519.PublicKey)), "main")
	if err := h2.m.SetServerFlags(id2, false, "", true, "test"); err != nil {
		t.Fatal(err)
	}
	h2.clock.Add(5 * time.Second)
	if status, out := h2.publish(p2.key, "main", publishBody("main", h2.listing(1, 0), port, nil)); status != 200 ||
		out["listed"] != true || out["probe"] != "skipped" {
		t.Fatalf("trusted: %d %v", status, out)
	}
}

// Applications are made with the Discord bot: the earlier endpoints answer
// 410, and core.Apply checks every field.
func TestApplications(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	for _, request := range [][2]string{{"POST", "/v1/applications"}, {"GET", "/v1/applications/challenge"},
		{"GET", "/v1/applications/a_x?token=y"}} {
		status, _, data := h.doWith(request[0], request[1], []byte(`{"name":"x"}`),
			map[string]string{"Content-Type": "application/json"})
		var out map[string]any
		_ = json.Unmarshal(data, &out)
		if status != 410 || code(out) != "applications_by_discord" {
			t.Errorf("%s %s: %d %v", request[0], request[1], status, out)
		}
	}
	key, _ := sign.NewSeed()
	public := sign.PublicKeyText(key.Public().(ed25519.PublicKey))
	nonce := h.m.ProofNonce("123456789012345678")
	base := func() core.ApplicationInput {
		return core.ApplicationInput{Name: "Milenko's servers", PublicKey: public, Servers: 2, Region: "eu",
			DiscordID: "123456789012345678", DiscordName: "milenko",
			Proof: &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}}
	}
	for name, change := range map[string]func(*core.ApplicationInput){
		"short name":  func(in *core.ApplicationInput) { in.Name = "ab" },
		"key":         func(in *core.ApplicationInput) { in.PublicKey = "ed25519:00" },
		"servers":     func(in *core.ApplicationInput) { in.Servers = 0 },
		"region":      func(in *core.ApplicationInput) { in.Region = "Europe!" },
		"discord id":  func(in *core.ApplicationInput) { in.DiscordID = "me" },
		"no proof":    func(in *core.ApplicationInput) { in.Proof = nil },
		"wrong proof": func(in *core.ApplicationInput) { in.Proof.Signature = strings.Repeat("00", 64) },
		"other nonce": func(in *core.ApplicationInput) {
			in.Proof = &core.Proof{Nonce: "opence-apply-1-0000000000000000", Signature: strings.Repeat("00", 64)}
		},
		// a nonce given to another Discord user, or to none
		"another's nonce": func(in *core.ApplicationInput) { in.DiscordID = "223456789012345678" },
		"unbound nonce": func(in *core.ApplicationInput) {
			n := h.m.ProofNonce("")
			in.Proof = &core.Proof{Nonce: n, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(n)))}
		},
	} {
		in := base()
		change(&in)
		var field *core.FieldError
		if _, err := h.m.Apply(in, "test"); !errors.As(err, &field) {
			t.Errorf("%s: %v", name, err)
		}
	}
	a, err := h.m.Apply(base(), "test")
	if err != nil || a.Status != "pending" || !a.ProofOK || a.DiscordID != "123456789012345678" ||
		a.Discord != "milenko" || a.Email != "" || !a.LogQueued {
		t.Fatalf("apply: %v %+v", err, a)
	}
	// the same key again: pending already
	in := base()
	in.DiscordID = ""
	in.Proof = h.proof(key)
	var action *core.ActionError
	if _, err := h.m.Apply(in, "cli"); !errors.As(err, &action) || action.Code != "duplicate" {
		t.Fatalf("again: %v", err)
	}
	// the publish of a pending key is told so
	if status, out := h.publish(key, "main", publishBody("main", h.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "publisher_pending" {
		t.Fatalf("pending: %d %v", status, out)
	}
	if _, err := h.m.Approve(a.ID, 0, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Apply(base(), "test"); !errors.As(err, &action) || action.Code != "key_exists" {
		t.Fatalf("an approved key: %v", err)
	}
}

func TestApplicationLimits(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Probe, c.ApplicationsPerDay, c.ApplicationsPerKey, c.ApplicationsPerHour = false, 2, 2, 5
	})
	logged := &lockedBuffer{}
	h.m.Notifier.Log = slog.New(slog.NewTextHandler(logged, nil))
	h.m.Log = h.m.Notifier.Log
	apply := func(discordID string) (*model.Application, error) {
		key, _ := sign.NewSeed()
		nonce := h.m.ProofNonce(discordID)
		return h.m.Apply(core.ApplicationInput{Name: "Operator", Servers: 1, DiscordID: discordID,
			DiscordName: "op", PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
			Proof: &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}},
			"test")
	}
	limited := func(err error) bool {
		var l *core.LimitError
		return errors.As(err, &l)
	}
	// one pending application at a time per Discord user
	first, err := apply("100000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	var action *core.ActionError
	if _, err := apply("100000000000000001"); !errors.As(err, &action) || action.Code != "duplicate" ||
		!strings.Contains(action.Message, first.ID) {
		t.Fatalf("a second pending application: %v", err)
	}
	// MASTER_APPLICATIONS_PER_DAY a day per Discord user
	if err := h.m.Deny(first.ID, "test", "test"); err != nil {
		t.Fatal(err)
	}
	second, err := apply("100000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.m.Deny(second.ID, "test", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := apply("100000000000000001"); !limited(err) {
		t.Fatalf("a third application of the day: %v", err)
	}
	// the hour's number (5), with a proof of key: not a refusal, but the
	// admins are alerted once it is reached, and the next ones that hour are
	// not announced (nor queued for the log channel) one by one
	for i := 2; i <= 4; i++ {
		if _, err := apply(fmt.Sprintf("10000000000000000%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	past, err := apply("100000000000000005")
	if err != nil || past.LogQueued {
		t.Fatalf("past the hour's number, with a proof: %v %+v", err, past)
	}
	if n := strings.Count(logged.String(), "New application"); n != 5 {
		t.Fatalf("%d applications announced, not 5:\n%s", n, logged.String())
	}
	if n := strings.Count(logged.String(), "MASTER_APPLICATIONS_PER_HOUR"); n != 1 {
		t.Fatalf("%d alerts, not 1:\n%s", n, logged.String())
	}
	h.clock.Add(time.Hour + time.Second)
	if a, err := apply("100000000000000006"); err != nil || !a.LogQueued {
		t.Fatalf("the next hour: %v", err)
	}
	if n := strings.Count(logged.String(), "New application"); n != 6 {
		t.Fatalf("the next hour's application not announced")
	}
	// a key: denied twice, then refused for the day
	key, _ := sign.NewSeed()
	for i := 0; i < 3; i++ {
		a, err := h.m.Apply(core.ApplicationInput{Name: "Operator", Servers: 1,
			PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey)), Proof: h.proof(key)}, "cli")
		if i == 2 {
			if !limited(err) {
				t.Fatalf("a third application for the key: %v", err)
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := h.m.Deny(a.ID, "test", "test"); err != nil {
			t.Fatal(err)
		}
	}
	// without MASTER_REQUIRE_PROOF, an application without a proof is
	// taken, and flagged
	open := newHarness(t, func(c *config.Config) { c.RequireProof = false })
	key, _ = sign.NewSeed()
	a, err := open.m.Apply(core.ApplicationInput{Name: "Operator", Servers: 1, DiscordID: "100000000000000009",
		DiscordName: "flagged.op", PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey))}, "test")
	if err != nil || a.ProofOK {
		t.Fatalf("%v %+v", err, a)
	}
	status, _, page := open.doWith("GET", "/admin/applications/"+a.ID, nil,
		map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 40)})
	if status != 200 || !strings.Contains(string(page), "No proof of key") ||
		!strings.Contains(string(page), "flagged.op") || !strings.Contains(string(page), "100000000000000009") {
		t.Fatalf("the admin page does not show the missing proof and the Discord applicant: %d", status)
	}
	status, _, page = open.doWith("GET", "/admin/applications", nil,
		map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 40)})
	if status != 200 || !strings.Contains(string(page), "flagged.op") {
		t.Fatalf("the list does not show the Discord applicant: %d", status)
	}
}

// lockedBuffer is a log's text, written from any goroutine.
type lockedBuffer struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.String()
}

// The hour's number refuses only applications without a proof of key, and
// only after the Discord user's and the key's limits.
func TestApplicationHourNumber(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Probe, c.RequireProof = false, false
		c.ApplicationsPerDay, c.ApplicationsPerKey, c.ApplicationsPerHour = 1, 2, 2
	})
	apply := func(discordID string, proven bool) error {
		key, _ := sign.NewSeed()
		in := core.ApplicationInput{Name: "Operator", Servers: 1, DiscordID: discordID,
			PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey))}
		if proven {
			nonce := h.m.ProofNonce(discordID)
			in.Proof = &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}
		}
		a, err := h.m.Apply(in, "test")
		if err == nil {
			err = h.m.Deny(a.ID, "test", "test")
		}
		return err
	}
	refusal := func(err error) string {
		var l *core.LimitError
		if !errors.As(err, &l) {
			return fmt.Sprint("not refused by a limit: ", err)
		}
		return l.Message
	}
	for i := 0; i < 2; i++ {
		if err := apply(fmt.Sprintf("20000000000000000%d", i), false); err != nil {
			t.Fatal(err)
		}
	}
	// the hour's 2 unproven are in, but the Discord user's limit is checked
	// first
	if why := refusal(apply("200000000000000000", false)); !strings.Contains(why, "from you") {
		t.Fatalf("the Discord user's limit not checked first: %s", why)
	}
	if why := refusal(apply("200000000000000002", false)); !strings.Contains(why, "without a proof") {
		t.Fatalf("an unproven application past the hour's number: %s", why)
	}
	// one with a proof is taken
	if err := apply("200000000000000003", true); err != nil {
		t.Fatalf("a proven application past the hour's number: %v", err)
	}
	h.clock.Add(time.Hour + time.Second)
	if err := apply("200000000000000004", false); err != nil {
		t.Fatalf("the next hour: %v", err)
	}
}

func TestPeersShareApprovalsAndRevocations(t *testing.T) {
	a := newHarness(t, func(c *config.Config) { c.Probe = false })
	b := newHarness(t, func(c *config.Config) { c.Probe = false })
	peerOf := func(h *harness) core.Peer {
		public := h.m.Key.Public().(ed25519.PublicKey)
		return core.Peer{URL: h.server.URL, Key: public, KeyID: sign.KeyID(public)}
	}
	a.m.Peers, b.m.Peers = []core.Peer{peerOf(b)}, []core.Peer{peerOf(a)}
	syncB := &peers.Syncer{Master: b.m, Client: http.DefaultClient}
	syncA := &peers.Syncer{Master: a.m, Client: http.DefaultClient}

	p := a.approved(2)
	if status, out := b.publish(p.key, "main", publishBody("main", b.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "unknown_key" {
		t.Fatalf("before the sync: %d %v", status, out)
	}
	syncB.SyncOnce(context.Background())
	if status, out := b.publish(p.key, "main", publishBody("main", b.listing(1, 0), 2302, nil)); status != 200 {
		t.Fatalf("after the sync: %d %v", status, out)
	}
	// b suspends; a learns it; b resumes; a lifts it
	if err := b.m.SetStatus(p.id, "suspended", "spam", "test"); err != nil {
		t.Fatal(err)
	}
	syncA.SyncOnce(context.Background())
	if state, _ := a.m.State(p.id); state.Status != "suspended" {
		t.Fatalf("a: %s", state.Status)
	}
	b.clock.Add(time.Second)
	if err := b.m.SetStatus(p.id, "approved", "", "test"); err != nil {
		t.Fatal(err)
	}
	syncA.SyncOnce(context.Background())
	if state, _ := a.m.State(p.id); state.Status != "approved" {
		t.Fatalf("a after the resume: %s", state.Status)
	}
	// a revokes the key; b refuses it and unlists its server
	a.clock.Add(time.Second)
	if err := a.m.RevokeKey(sign.KeyID(p.key.Public().(ed25519.PublicKey)), "stolen", "test"); err != nil {
		t.Fatal(err)
	}
	syncB.SyncOnce(context.Background())
	if list, _, _ := b.list(""); len(list["servers"].([]any)) != 0 {
		t.Fatal("b lists a revoked key's server")
	}
	b.clock.Add(6 * time.Second)
	if status, out := b.publish(p.key, "main", publishBody("main", b.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "key_revoked" {
		t.Fatalf("b after the revocation: %d %v", status, out)
	}
	// a master not configured as a peer is refused
	stranger, _ := sign.NewSeed()
	status, out := a.signed(stranger, "GET", "/v1/publishers?since=0", nil)
	if status != 403 || code(out) != "not_a_peer" {
		t.Fatalf("stranger: %d %v", status, out)
	}
	if state, err := b.m.Store.Peer(peerOf(a).KeyID); err != nil || state.LastError != "" || state.LastOK == 0 {
		t.Fatalf("peer state %+v %v", state, err)
	}
}

// A publisher new here is recorded as come from the peer whose record it
// is, not from the origin that record claims; only that peer renames it.
func TestPeerOrigin(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	peerKey, _ := sign.NewSeed()
	otherKey, _ := sign.NewSeed()
	peerID, otherID := sign.KeyID(peerKey.Public().(ed25519.PublicKey)), sign.KeyID(otherKey.Public().(ed25519.PublicKey))
	h.m.Peers = []core.Peer{{URL: "https://peer.example", Key: peerKey.Public().(ed25519.PublicKey), KeyID: peerID},
		{URL: "https://other.example", Key: otherKey.Public().(ed25519.PublicKey), KeyID: otherID}}
	approved := model.Approved
	record := func(name, origin string, updated int64) []peers.Shared {
		return []peers.Shared{{ID: "p_claimed", Name: name, Status: &approved, Since: 1, Updated: updated,
			Origin: origin, Keys: []peers.SharedKey{}}}
	}
	// the peer claims the other peer (or this master) approved it
	for _, claim := range []string{otherID, h.m.KeyID} {
		if _, err := peers.Apply(h.m, peerID, record("Claimed", claim, 10)); err != nil {
			t.Fatal(err)
		}
		if p, err := h.m.Store.Publisher("p_claimed"); err != nil || p.Origin != peerID {
			t.Fatalf("claimed %s: %+v %v", claim, p, err)
		}
	}
	// the other peer cannot rename it; the peer it came from can
	if _, err := peers.Apply(h.m, otherID, record("Renamed", otherID, 20)); err != nil {
		t.Fatal(err)
	}
	if p, _ := h.m.Store.Publisher("p_claimed"); p.Name != "Claimed" {
		t.Fatalf("renamed by another peer: %q", p.Name)
	}
	if _, err := peers.Apply(h.m, peerID, record("Renamed", otherID, 30)); err != nil {
		t.Fatal(err)
	}
	if p, _ := h.m.Store.Publisher("p_claimed"); p.Name != "Renamed" {
		t.Fatalf("not renamed by its peer: %q", p.Name)
	}
}

func TestUntrustedPeerIgnored(t *testing.T) {
	a := newHarness(t, func(c *config.Config) { c.Probe = false })
	b := newHarness(t, func(c *config.Config) { c.Probe = false; c.PeersTrust = "none" })
	public := a.m.Key.Public().(ed25519.PublicKey)
	b.m.Peers = []core.Peer{{URL: a.server.URL, Key: public, KeyID: sign.KeyID(public)}}
	publicB := b.m.Key.Public().(ed25519.PublicKey)
	a.m.Peers = []core.Peer{{URL: b.server.URL, Key: publicB, KeyID: sign.KeyID(publicB)}}
	p := a.approved(2)
	// fetched by hand: the records arrive, but count for nothing
	r, err := (&peers.Syncer{Master: b.m, Client: http.DefaultClient}).Fetch(context.Background(), b.m.Peers[0], 0)
	if err != nil || len(r.Publishers) != 1 {
		t.Fatalf("%v %v", err, r)
	}
	if _, err := peers.Apply(b.m, sign.KeyID(public), r.Publishers); err != nil {
		t.Fatal(err)
	}
	if status, out := b.publish(p.key, "main", publishBody("main", b.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "unknown_key" {
		t.Fatalf("untrusted approval used: %d %v", status, out)
	}
}

func TestExportImport(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	p := h.approved(3)
	e, err := h.m.Store.Export(h.m.KeyID, false)
	if err != nil || len(e.Publishers) != 1 || len(e.Applications) != 1 {
		t.Fatalf("%v %+v", err, e)
	}
	fresh, _ := store.Open(":memory:")
	defer fresh.Close()
	counts, err := fresh.Import(e, h.m.KeyID)
	if err != nil || counts.Publishers != 1 || counts.Opinions != 1 || counts.Keys != 1 || counts.Applications != 1 {
		t.Fatalf("%v %+v", err, counts)
	}
	again, _ := fresh.Import(e, h.m.KeyID)
	if again.Publishers+again.Opinions+again.Keys+again.Applications != 0 {
		t.Fatalf("an import twice changed %+v", again)
	}
	restored, _ := core.New(fresh, h.m.Key, h.m.Config, h.m.Notifier, h.m.Log)
	state, err := restored.State(p.id)
	if err != nil || state.Status != "approved" || state.Quota != 3 || len(state.Keys) != 1 {
		t.Fatalf("%v %+v", err, state)
	}
}

func TestPagesAndMetrics(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	p := h.approved(2)
	h.publish(p.key, "main", publishBody("main", h.listing(3, 0), 2302, nil))
	for _, path := range []string{"/", "/apply", "/healthz", "/metrics", "/v1/master", "/static/style.css",
		"/v1/publishers/" + p.id, "/admin/login"} {
		status, header, data := h.do("GET", path, nil, "")
		if status != 200 {
			t.Errorf("%s: %d", path, status)
		}
		if strings.HasPrefix(header.Get("Content-Type"), "text/html") &&
			!strings.Contains(header.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("%s: no CSP", path)
		}
		if path == "/" && !strings.Contains(string(data), "Test server") {
			t.Errorf("the list page lacks the server")
		}
		if path == "/metrics" {
			for _, name := range []string{"master_servers{reachable=\"true\"}", "master_publishers{status=\"approved\"} 1",
				"master_publishes_total{result=\"ok\"} 1", "master_probes_total", "master_list_requests_total",
				"master_build_info"} {
				if !strings.Contains(string(data), name) {
					t.Errorf("metrics lack %s", name)
				}
			}
		}
	}
	// the admin pages need the token, then a CSRF token on every form
	request, _ := http.NewRequest("GET", h.server.URL+"/admin/applications", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("admin with the token: %v %d", err, response.StatusCode)
	}
	response.Body.Close()
	request, _ = http.NewRequest("GET", h.server.URL+"/admin/applications", nil)
	request.Header.Set("Authorization", "Bearer wrong")
	response, _ = http.DefaultClient.Do(request)
	if response.StatusCode != 401 {
		t.Fatalf("admin with a wrong token: %d", response.StatusCode)
	}
	response.Body.Close()
}

// A listing's host key is published by one publisher at a time: another
// publisher's copy of its bytes is refused while it is live.
func TestListingBoundToItsPublisher(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.PublishInterval = 0 })
	owner, thief := h.approved(4), h.approved(4)
	host, _ := sign.NewSeed()
	bytes := listing.Make(host, listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen, Sequence: 1,
		Time: uint32(h.clock.Now().Unix()), Players: 1, MaxPlayers: 16, Name: "Owned", Map: "bloodgulch",
		Gametype: "CTF"})
	if status, out := h.publish(owner.key, "main", publishBody("main", bytes, 2302, nil)); status != 200 {
		t.Fatalf("owner: %d %v", status, out)
	}
	status, out := h.publish(thief.key, "copy", publishBody("copy", bytes, 2302, nil))
	if status != 403 || code(out) != "listing_taken" {
		t.Fatalf("a copied listing: %d %v", status, out)
	}
	// the same publisher's other instance may carry it (a key's rotation)
	if status, out := h.publish(owner.key, "second", publishBody("second", bytes, 2303, nil)); status != 200 {
		t.Fatalf("the owner's second instance: %d %v", status, out)
	}
	// once the owner's servers are gone, the host key is free
	ownerID := sign.KeyID(owner.key.Public().(ed25519.PublicKey))
	for _, instance := range []string{"main", "second"} {
		if status, _ := h.signed(owner.key, "DELETE", "/v1/servers/"+sign.ServerID(ownerID, instance), nil); status != 200 {
			t.Fatalf("delete %s: %d", instance, status)
		}
	}
	if status, out := h.publish(thief.key, "copy", publishBody("copy", bytes, 2302, nil)); status != 200 {
		t.Fatalf("after the owner closed: %d %v", status, out)
	}
}

// A publisher that copied a host's listing while the host's own publisher
// was not publishing holds the host key only while it brings newer listings:
// one replaying a copy loses it, after BindingStale, to a newer listing. A
// refusal is in the audit log and on the admin servers page, and an admin
// settles a dispute by hiding the copy.
func TestListingTakenOver(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.PublishInterval = 0 })
	owner, thief := h.approved(4), h.approved(4)
	host, _ := sign.NewSeed()
	sequence := uint32(0)
	fresh := func() []byte {
		sequence++
		return listing.Make(host, listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen, Sequence: sequence,
			Time: uint32(h.clock.Now().Unix()), Players: 1, MaxPlayers: 16, Name: "Owned", Map: "bloodgulch",
			Gametype: "CTF"})
	}
	thiefID := sign.ServerID(sign.KeyID(thief.key.Public().(ed25519.PublicKey)), "copy")
	ownerID := sign.ServerID(sign.KeyID(owner.key.Public().(ed25519.PublicKey)), "main")
	first := fresh()
	if status, out := h.publish(owner.key, "main", publishBody("main", first, 2302, nil)); status != 200 {
		t.Fatalf("owner: %d %v", status, out)
	}
	// the owner's publishes stop for longer than the TTL; the thief copies
	h.clock.Add(core.TTL + time.Second)
	if status, out := h.publish(thief.key, "copy", publishBody("copy", first, 2302, nil)); status != 200 {
		t.Fatalf("the copy, in the gap: %d %v", status, out)
	}
	// the owner is back with a newer listing, but the copy is not stale yet
	h.clock.Add(core.Interval)
	if status, out := h.publish(owner.key, "main", publishBody("main", fresh(), 2302, nil)); status != 403 ||
		code(out) != "listing_taken" {
		t.Fatalf("the owner, the copy fresh: %d %v", status, out)
	}
	entries, err := h.m.Store.AuditActions("listing-taken", 0, 10)
	if err != nil || len(entries) != 1 || entries[0].Target != ownerID || !strings.Contains(entries[0].Detail, thiefID) {
		t.Fatalf("the refusal's audit entry: %v %+v", err, entries)
	}
	// (once an hour per server and holder)
	h.publish(owner.key, "main", publishBody("main", fresh(), 2302, nil))
	if entries, _ := h.m.Store.AuditActions("listing-taken", 0, 10); len(entries) != 1 {
		t.Fatalf("%d audit entries for one dispute", len(entries))
	}
	status, _, page := h.doWith("GET", "/admin/servers", nil,
		map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 40)})
	if status != 200 || !strings.Contains(string(page), "Disputed listings") || !strings.Contains(string(page), ownerID) {
		t.Fatalf("the admin servers page does not show the dispute: %d", status)
	}
	// the thief replays its copy, the owner's listings go on; once the copy
	// has gone BindingStale without a newer listing, a newer one takes it
	for i := 0; i < 3; i++ {
		h.clock.Add(core.Interval)
		if status, out := h.publish(thief.key, "copy", publishBody("copy", first, 2302, nil)); status != 200 {
			t.Fatalf("the replayed copy: %d %v", status, out)
		}
		fresh()
	}
	if status, out := h.publish(owner.key, "main", publishBody("main", fresh(), 2302, nil)); status != 200 {
		t.Fatalf("the owner, the copy stale: %d %v", status, out)
	}
	if server, _ := h.m.Store.Server(thiefID); !server.Closed {
		t.Fatal("the stale copy's server is not closed")
	}
	if entries, _ := h.m.Store.AuditActions("listing-taken-over", 0, 10); len(entries) != 1 ||
		entries[0].Target != thiefID {
		t.Fatalf("the takeover's audit entry: %+v", entries)
	}
	if list, _, _ := h.list(""); len(list["servers"].([]any)) != 1 ||
		list["servers"].([]any)[0].(map[string]any)["id"] != ownerID {
		t.Fatalf("the list: %v", list["servers"])
	}
	// the owner's listings are renewed: a copy of the newest is refused
	h.clock.Add(core.Interval)
	newest := fresh()
	if status, out := h.publish(owner.key, "main", publishBody("main", newest, 2302, nil)); status != 200 {
		t.Fatalf("owner: %d %v", status, out)
	}
	if status, out := h.publish(thief.key, "copy", publishBody("copy", newest, 2302, nil)); status != 403 ||
		code(out) != "listing_taken" {
		t.Fatalf("a copy of the owner's newest: %d %v", status, out)
	}
	// (a thief that keeps copying the newest listings is not displaced by
	// this rule: an admin settles it by hiding the holder's server, which
	// then holds nothing; shown here with the owner's, the holder now)
	if err := h.m.SetServerFlags(ownerID, true, "test", false, "test"); err != nil {
		t.Fatal(err)
	}
	if status, out := h.publish(thief.key, "copy", publishBody("copy", newest, 2302, nil)); status != 200 {
		t.Fatalf("past a hidden holder: %d %v", status, out)
	}
}

// A publisher's new instances make records up to its quota and
// DormantInstances; past that the oldest dormant ones are dropped.
func TestInstanceRecordsCapped(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.PublishInterval = 0 })
	p := h.approved(1)
	for i := 0; i < 3*api.DormantInstances; i++ {
		instance := fmt.Sprintf("i%d", i)
		if status, out := h.publish(p.key, instance, publishBody(instance, h.listing(1, 0), 2302, nil)); status != 200 {
			t.Fatalf("instance %d: %d %v", i, status, out)
		}
		h.clock.Add(core.TTL + time.Second)
	}
	n, err := h.m.Store.CountServers(p.id)
	if err != nil || n > 1+api.DormantInstances {
		t.Fatalf("%d records (%v)", n, err)
	}
	// flagged records are kept: past the cap, a new instance is refused
	servers, _ := h.m.Store.PublisherServers(p.id)
	for _, v := range servers {
		if err := h.m.SetServerFlags(v.ID, true, "kept", false, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if status, out := h.publish(p.key, "new", publishBody("new", h.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "too_many_instances" {
		t.Fatalf("past the cap: %d %v", status, out)
	}
}

// The probe and served addresses are globally routable ones.
func TestPublishAddresses(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.PublishInterval = 0 })
	p := h.approved(4)
	for _, bad := range []string{"100.64.0.1:2302", "192.0.0.8:2302", "198.18.0.1:2302", "240.0.0.1:2302",
		"[fec0::1]:2302", "[64:ff9b::a00:1]:2302", "[2002:a00:1::1]:2302", "[2001:db8::1]:2302", "[fe80::1]:2302",
		"224.0.0.1:2302", "0.0.0.0:2302"} {
		status, out := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), 2302,
			map[string]any{"address": bad}))
		if status != 400 || code(out) != "schema" {
			t.Errorf("%s: %d %v", bad, status, out)
		}
	}
	for _, good := range []string{"8.8.8.8:2302", "[2606:4700::1]:2302", "[::ffff:8.8.4.4]:2302",
		"[64:ff9b::808:808]:2302", "127.0.0.1:2302"} {
		status, out := h.publish(p.key, "main", publishBody("main", h.listing(1, 0), 2302,
			map[string]any{"address": good}))
		if status != 200 {
			t.Errorf("%s: %d %v", good, status, out)
		}
	}
	// from a public source, a private address is refused
	q := newHarness(t, func(c *config.Config) { c.Probe = false; c.TrustedProxies = "127.0.0.1" })
	pub := q.approved(4)
	body := publishBody("main", q.listing(1, 0), 2302, map[string]any{"address": "192.168.1.5:2302"})
	path := "/v1/servers/" + sign.ServerID(sign.KeyID(pub.key.Public().(ed25519.PublicKey)), "main")
	status, _, data := q.doWith("PUT", path, body, map[string]string{
		"Authorization":     sign.Authorization(pub.key, q.m.KeyID, "PUT", path, body, q.clock.Now(), sign.NewNonce()),
		"X-Forwarded-For":   "[2606:4700::9]:51000",
		"X-Forwarded-Proto": "https",
	})
	if status != 400 || !strings.Contains(string(data), "public address") {
		t.Fatalf("a private address from a public source: %d %s", status, data)
	}
}

// An import takes records in this master's name only from its own export.
func TestImportRefusesThisMastersName(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	stranger, _ := sign.NewSeed()
	strangerID := sign.KeyID(stranger.Public().(ed25519.PublicKey))
	victim, _ := sign.NewSeed()
	victimPublic := sign.PublicKeyText(victim.Public().(ed25519.PublicKey))
	victimID := sign.KeyID(victim.Public().(ed25519.PublicKey))
	e := &store.Export{Format: store.ExportFormat, Master: strangerID, Publishers: []store.ExportedPublisher{{
		Publisher: model.Publisher{ID: "p_forged", Name: "Forged", Origin: h.m.KeyID, Since: 1, Created: 1, Updated: 1},
		Opinions: []model.Opinion{{Source: h.m.KeyID, Status: model.Approved, Quota: 1000, Updated: 2},
			{Source: strangerID, Status: model.Approved, Quota: 4, Updated: 2},
			{Source: strangerID, Status: "owner", Quota: 4, Updated: 3}},
		Keys: []model.KeyRecord{{KeyID: victimID, Source: h.m.KeyID, PublicKey: victimPublic, Status: "active",
			Updated: 2},
			{KeyID: "0123456789abcdef", Source: strangerID, PublicKey: victimPublic, Status: "active", Updated: 2},
			{KeyID: strangerID, Source: strangerID, PublicKey: "ed25519:zz", Status: "active", Updated: 2}},
	}}}
	counts, err := h.m.Store.Import(e, h.m.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Publishers != 1 || counts.Opinions != 1 || counts.Keys != 0 || counts.Refused != 5 {
		t.Fatalf("%+v", counts)
	}
	// nothing in this master's name: nothing shared, the key unknown
	records, _ := peers.Records(h.m, 0)
	if len(records) != 0 {
		t.Fatalf("this master shares a forged record: %+v", records)
	}
	if _, err := h.m.Identify(victimID); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("the forged key: %v", err)
	}
	if status, out := h.publish(victim, "main", publishBody("main", h.listing(1, 0), 2302, nil)); status != 403 ||
		code(out) != "unknown_key" {
		t.Fatalf("a publish with the forged key: %d %v", status, out)
	}
	// this master's own export is taken whole
	e.Master = h.m.KeyID
	e.Publishers[0].Keys = e.Publishers[0].Keys[:1]
	counts, err = h.m.Store.Import(e, h.m.KeyID)
	if err != nil || counts.Opinions != 1 || counts.Keys != 1 {
		t.Fatalf("%v %+v", err, counts)
	}
}

// Admin notices are not read from the URL; HSTS over TLS.
func TestFlashAndHSTS(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.TrustedProxies = "127.0.0.1" })
	var page []byte
	// a notice in the URL is not shown
	_, _, page = h.doWith("GET", "/admin/applications?notice=Approved%3A+all&error=x", nil,
		map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 40)})
	if strings.Contains(string(page), "Approved: all") {
		t.Fatal("a notice read from the URL")
	}
	// HSTS for a request the trusted proxy took over TLS
	request := httptest.NewRequest("GET", "/healthz", nil)
	request.RemoteAddr = "127.0.0.1:4000"
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()
	h.api.Clients.HSTS(h.mux).ServeHTTP(recorder, request)
	if recorder.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS over TLS")
	}
}

// The list page, a publisher's page and the metrics share the list limit.
func TestPublicEndpointsLimited(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.ListPerMinute = 2 })
	for _, path := range []string{"/metrics", "/v1/publishers/p_nobody", "/"} {
		statuses := []int{}
		for i := 0; i < 4; i++ {
			status, _, _ := h.do("GET", path, nil, "")
			statuses = append(statuses, status)
		}
		if statuses[len(statuses)-1] != 429 {
			t.Errorf("%s: %v", path, statuses)
		}
		h.clock.Add(2 * time.Minute)
	}
}
