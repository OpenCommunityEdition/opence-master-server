package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

func (h *harness) pass(player ed25519.PrivateKey, ts int64) (int, map[string]any, []byte) {
	h.t.Helper()
	status, headers, data := h.do("GET", "/v1/pass?"+sign.SignPlayerQuery(player, sign.PassGetLabel, h.m.KeyID, ts),
		nil, "")
	if headers.Get("Access-Control-Allow-Origin") != "*" || headers.Get("Cache-Control") != "no-store" {
		h.t.Fatalf("headers %v", headers)
	}
	var answer map[string]any
	if status != 200 {
		_ = json.Unmarshal(data, &answer)
	}
	return status, answer, data
}

func errorCode(answer map[string]any) string {
	if e, ok := answer["error"].(map[string]any); ok {
		code, _ := e["code"].(string)
		return code
	}
	return ""
}

func TestPassEndpoint(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.LinkMaxKeys = 2 })
	player, _ := sign.NewSeed()
	public := player.Public().(ed25519.PublicKey)
	now := h.clock.Now().Unix()
	status, answer, _ := h.pass(player, now)
	if status != 404 || errorCode(answer) != "not_linked" {
		t.Fatalf("%d %v", status, answer)
	}
	if err := h.m.SaveLink(public, "80351110224678912", "nelly", sign.PassFlagGuild, "cli"); err != nil {
		t.Fatal(err)
	}
	status, _, data := h.pass(player, now)
	if status != 200 || len(data) != sign.PassSize {
		t.Fatalf("%d %x", status, data)
	}
	pass, err := sign.ReadPass(data, h.m.Key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if pass.DiscordID != 80351110224678912 || pass.DiscordName != "nelly" || pass.Flags != 1 ||
		!pass.Player.Equal(public) || pass.Expires-pass.Issued != 72*3600 || pass.Issued != h.clock.Now().Unix() {
		t.Fatalf("%+v", pass)
	}
	link, _ := h.m.Store.LinkOf(hex.EncodeToString(pass.Player))
	if link == nil || link.LastPass != pass.Issued {
		t.Fatalf("last pass not recorded: %+v", link)
	}
	// refusals
	if status, answer, _ := h.pass(player, now-301); status != 401 || errorCode(answer) != "clock" {
		t.Fatalf("%d %v", status, answer)
	}
	status, _, _ = h.do("GET", "/v1/pass?"+sign.SignPlayerQuery(player, sign.PassGetLabel, "0123456789abcdef", now),
		nil, "")
	if status != 401 {
		t.Fatalf("signed for another master: %d", status)
	}
	status, _, data = h.do("GET", "/v1/pass?"+sign.SignPlayerQuery(player, sign.LinkLabel, h.m.KeyID, now), nil, "")
	if status != 401 {
		t.Fatalf("a link's signature: %d", status)
	}
	if status, _, _ := h.do("GET", "/v1/pass?key=00&ts=1&sig=00", nil, ""); status != 401 {
		t.Fatalf("malformed: %d", status)
	}
	small := "0100000000000000000000000000000000000000000000000000000000000000"
	status, _, data = h.do("GET", "/v1/pass?key="+small+"&ts="+strconv.FormatInt(now, 10)+"&sig="+
		strings.Repeat("0", 128), nil, "")
	if status != 401 {
		t.Fatalf("a small-order key: %d %s", status, data)
	}

	// revoked: 403 with the reason, and no relinking
	n, err := h.m.RevokeAccount("80351110224678912", "cheating", "admin")
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	status, answer, _ = h.pass(player, now)
	if status != 403 || errorCode(answer) != "link_revoked" || answer["error"].(map[string]any)["message"] != "cheating" {
		t.Fatalf("%d %v", status, answer)
	}
	if err := h.m.SaveLink(public, "80351110224678912", "nelly", 0, "cli"); err == nil {
		t.Fatal("a revoked account linked again")
	}
	if err := h.m.LiftRevocation("80351110224678912", "admin"); err != nil {
		t.Fatal(err)
	}
	if status, answer, _ := h.pass(player, now); status != 404 {
		t.Fatalf("lifted: %d %v", status, answer)
	}
	for _, action := range []string{"link", "revoke-link", "lift-revocation"} {
		if entries, _ := h.m.Store.AuditActions(action, 0, 10); len(entries) == 0 {
			t.Errorf("no %s in the audit log", action)
		}
	}
}

// A key moves to the account that links it last; an account past its
// keys drops the least recently used.
func TestLinkKeys(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.LinkMaxKeys = 2 })
	var keys []ed25519.PrivateKey
	for range 3 {
		k, _ := sign.NewSeed()
		keys = append(keys, k)
	}
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	account := "80351110224678912"
	if err := h.m.SaveLink(pub(keys[0]), account, "nelly", 0, "cli"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	if err := h.m.SaveLink(pub(keys[1]), account, "nelly", 0, "cli"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	// the first key is used: the second is the least recently used
	if status, _, _ := h.pass(keys[0], h.clock.Now().Unix()); status != 200 {
		t.Fatal(status)
	}
	h.clock.Add(time.Minute)
	if err := h.m.SaveLink(pub(keys[2]), account, "nelly2", 0, "cli"); err != nil {
		t.Fatal(err)
	}
	links, _ := h.m.Store.AccountLinks(account)
	if len(links) != 2 || links[0].KeyID != sign.KeyID(pub(keys[2])) || links[1].KeyID != sign.KeyID(pub(keys[0])) ||
		links[1].DiscordName != "nelly2" {
		t.Fatalf("%+v", links)
	}
	// another account links the first key: it moves
	if err := h.m.SaveLink(pub(keys[0]), "80351110224678913", "other", 0, "cli"); err != nil {
		t.Fatal(err)
	}
	if links, _ := h.m.Store.AccountLinks(account); len(links) != 1 {
		t.Fatalf("%+v", links)
	}
	// unused 90 days: deleted
	h.clock.Add(store.LinkRetention + time.Hour)
	if err := h.m.Store.Purge(sign.NonceWindow, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if links, _ := h.m.Store.SearchLinks("", 10); len(links) != 0 {
		t.Fatalf("%+v", links)
	}
}

func TestPassRateLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.ListPerMinute = 1000 })
	player, _ := sign.NewSeed()
	statuses := map[int]int{}
	for range 32 {
		status, _, _ := h.pass(player, h.clock.Now().Unix())
		statuses[status]++
	}
	if statuses[404] != 30 || statuses[429] != 2 {
		t.Fatalf("%v", statuses)
	}
}
