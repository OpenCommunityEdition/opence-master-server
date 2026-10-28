package web_test

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

const clientSecret = "client-secret-for-the-tests_0123"

// fakeDiscord is Discord's OAuth2 and membership API, on loopback: a code
// is a user id; the members are in members.
type fakeDiscord struct {
	mu      sync.Mutex
	names   map[string]string
	members map[string]bool
	tokens  int
}

func (f *fakeDiscord) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/api/oauth2/token" && r.Method == "POST":
		id, secret, _ := r.BasicAuth()
		r.ParseForm()
		if id != "123456789012345678" || secret != clientSecret || r.PostForm.Get("grant_type") != "authorization_code" ||
			!strings.HasSuffix(r.PostForm.Get("redirect_uri"), "/link/callback") {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if _, ok := f.names[r.PostForm.Get("code")]; !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		f.tokens++
		json.NewEncoder(w).Encode(map[string]string{"access_token": "token-" + r.PostForm.Get("code"),
			"token_type": "Bearer"})
	case r.URL.Path == "/api/users/@me":
		id := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer token-")
		json.NewEncoder(w).Encode(map[string]string{"id": id, "username": f.names[id]})
	case strings.HasPrefix(r.URL.Path, "/api/guilds/223456789012345678/members/"):
		if r.Header.Get("Authorization") != "Bot bot-token" {
			http.Error(w, "{}", http.StatusUnauthorized)
			return
		}
		if !f.members[strings.TrimPrefix(r.URL.Path, "/api/guilds/223456789012345678/members/")] {
			http.Error(w, `{"message":"Unknown Member","code":10007}`, http.StatusNotFound)
			return
		}
		io.WriteString(w, "{}")
	default:
		http.NotFound(w, r)
	}
}

type linking struct{ settings discord.LinkSettings }

func (l linking) LinkSettings() discord.LinkSettings { return l.settings }

type linkHarness struct {
	t       *testing.T
	m       *core.Master
	pages   *web.Pages
	server  *httptest.Server
	discord *fakeDiscord
}

func newLinkHarness(t *testing.T, change func(*config.Config)) *linkHarness {
	values := config.Flags(flag.NewFlagSet("test", flag.ContinueOnError))
	for _, o := range config.Options {
		*values[o.Env] = o.Default
	}
	cfg, err := config.Load(values)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name = "Link master"
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := sign.NewSeed()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := core.New(st, key, cfg, &mail.Notifier{Log: log, Client: http.DefaultClient, Sync: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := web.New(m, &httpx.Clients{})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeDiscord{names: map[string]string{"80351110224678912": "nelly", "1300000000000000000": "newbie"},
		members: map[string]bool{"80351110224678912": true}}
	discordServer := httptest.NewServer(fake)
	pages.OAuth = discord.NewOAuth(http.DefaultClient)
	pages.OAuth.API, pages.OAuth.Authorize = discordServer.URL+"/api", discordServer.URL+"/authorize"
	pages.Linking = linking{discord.LinkSettings{ClientID: "123456789012345678", ClientSecret: clientSecret,
		BotToken: "bot-token", Guild: "223456789012345678", Invite: "https://discord.gg/opence"}}
	mux := http.NewServeMux()
	pages.Routes(mux)
	server := httptest.NewServer(mux)
	m.Config.PublicURL = server.URL
	if change != nil {
		change(m.Config)
	}
	t.Cleanup(func() {
		server.Close()
		discordServer.Close()
		st.Close()
	})
	return &linkHarness{t: t, m: m, pages: pages, server: server, discord: fake}
}

// browser is a client with cookies that follows no redirect.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (h *linkHarness) get(c *http.Client, link string) (int, http.Header, string) {
	h.t.Helper()
	response, err := c.Get(link)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(body)
}

func (h *linkHarness) post(c *http.Client, link string, form url.Values) (int, http.Header, string) {
	h.t.Helper()
	response, err := c.PostForm(link, form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(body)
}

var statePattern = regexp.MustCompile(`state=([0-9a-f]{32})`)

// start opens a link page for a player key: the state Discord's link
// carries.
func (h *linkHarness) start(c *http.Client, player ed25519.PrivateKey) (string, string) {
	h.t.Helper()
	ts := h.m.Now().Unix()
	status, _, page := h.get(c, h.server.URL+"/link?"+sign.SignPlayerQuery(player, sign.LinkLabel, h.m.KeyID, ts))
	code := sign.LinkCode(player.Public().(ed25519.PublicKey), itoa(ts))
	if status != 200 || !strings.Contains(page, "Link Discord to the OpenCE game showing "+code) ||
		!strings.Contains(page, "Continue with Discord") {
		h.t.Fatalf("%d %s", status, page)
	}
	match := statePattern.FindStringSubmatch(page)
	if match == nil {
		h.t.Fatalf("no state in %s", page)
	}
	if !strings.Contains(page, "scope=identify") || !strings.Contains(page, "client_id=123456789012345678") ||
		!strings.Contains(page, url.QueryEscape(h.server.URL+"/link/callback")) {
		h.t.Fatalf("the authorize link: %s", page)
	}
	return match[1], code
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestLinkFlow(t *testing.T) {
	h := newLinkHarness(t, nil)
	c := browser()
	player, _ := sign.NewSeed()
	public := player.Public().(ed25519.PublicKey)
	state, code := h.start(c, player)
	status, _, page := h.get(c, h.server.URL+"/link/callback?code=80351110224678912&state="+state)
	if status != 200 || !strings.Contains(page, "Linked as nelly. Go back to the game.") || !strings.Contains(page, code) {
		t.Fatalf("%d %s", status, page)
	}
	link, err := h.m.Store.LinkOf(hexKey(public))
	if err != nil || link.DiscordID != "80351110224678912" || link.Flags != sign.PassFlagGuild {
		t.Fatalf("%+v %v", link, err)
	}
	entries, _ := h.m.Store.AuditActions("link", 0, 10)
	if len(entries) != 1 || entries[0].Actor != "discord:80351110224678912 nelly" {
		t.Fatalf("%+v", entries)
	}
	// the state is good once
	status, _, _ = h.get(c, h.server.URL+"/link/callback?code=80351110224678912&state="+state)
	if status != 400 {
		t.Fatalf("a state taken twice: %d", status)
	}
	// another browser (no cookie) cannot use a state
	state, _ = h.start(c, player)
	status, _, page = h.get(browser(), h.server.URL+"/link/callback?code=80351110224678912&state="+state)
	if status != 400 || !strings.Contains(page, "not this browser") {
		t.Fatalf("%d %s", status, page)
	}
	// the player cancels on Discord
	state, _ = h.start(c, player)
	status, _, page = h.get(c, h.server.URL+"/link/callback?error=access_denied&state="+state)
	if status != 200 || !strings.Contains(page, "Nothing was linked") {
		t.Fatalf("%d %s", status, page)
	}

	// manage: log in with Discord, list, unlink, delete everything
	status, _, page = h.get(c, h.server.URL+"/link/manage")
	if status != 200 || !strings.Contains(page, "Log in with Discord") {
		t.Fatalf("%d %s", status, page)
	}
	status, headers, _ := h.get(c, h.server.URL+"/link/manage/login")
	location := headers.Get("Location")
	match := statePattern.FindStringSubmatch(location)
	if status != 303 || !strings.HasPrefix(location, h.discordURL()+"/authorize?") || match == nil {
		t.Fatalf("%d %s", status, location)
	}
	status, headers, _ = h.get(c, h.server.URL+"/link/callback?code=80351110224678912&state="+match[1])
	if status != 303 || headers.Get("Location") != "/link/manage" {
		t.Fatalf("%d %v", status, headers)
	}
	status, _, page = h.get(c, h.server.URL+"/link/manage")
	if status != 200 || !strings.Contains(page, sign.KeyID(public)) || !strings.Contains(page, "Delete everything") {
		t.Fatalf("%d %s", status, page)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`).FindStringSubmatch(page)[1]
	status, _, _ = h.post(c, h.server.URL+"/link/manage/unlink", url.Values{"csrf": {"wrong"}, "key": {hexKey(public)}})
	if status != 403 {
		t.Fatalf("a wrong CSRF token: %d", status)
	}
	request, _ := http.NewRequest("POST", h.server.URL+"/link/manage/unlink",
		strings.NewReader(url.Values{"csrf": {csrf}, "key": {hexKey(public)}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://evil.example")
	if response, _ := c.Do(request); response.StatusCode != 403 {
		t.Fatalf("another origin: %d", response.StatusCode)
	}
	status, _, _ = h.post(c, h.server.URL+"/link/manage/unlink", url.Values{"csrf": {csrf}, "key": {hexKey(public)}})
	if status != 303 {
		t.Fatal(status)
	}
	if _, err := h.m.Store.LinkOf(hexKey(public)); err == nil {
		t.Fatal("not unlinked")
	}
	if entries, _ := h.m.Store.AuditActions("unlink", 0, 10); len(entries) != 1 ||
		entries[0].Actor != "discord:80351110224678912 nelly" {
		t.Fatalf("%+v", entries)
	}
	status, _, page = h.post(c, h.server.URL+"/link/manage/delete", url.Values{"csrf": {csrf}})
	if status != 200 || !strings.Contains(page, "Everything is deleted") {
		t.Fatalf("%d %s", status, page)
	}
	status, _, page = h.get(c, h.server.URL+"/link/manage")
	if !strings.Contains(page, "Log in with Discord") {
		t.Fatal("still logged in")
	}
}

func (h *linkHarness) discordURL() string {
	return strings.TrimSuffix(h.pages.OAuth.Authorize, "/authorize")
}

func hexKey(public ed25519.PublicKey) string {
	return strings.TrimPrefix(sign.PublicKeyText(public), sign.PublicKeyPrefix)
}

func TestLinkRules(t *testing.T) {
	h := newLinkHarness(t, func(c *config.Config) { c.LinkMinAccountDays = 30; c.LinkRequireGuild = true })
	c := browser()
	player, _ := sign.NewSeed()
	// an account made yesterday (its id's top bits) is too new
	young := strconv.FormatUint(uint64(time.Now().Add(-24*time.Hour).UnixMilli()-1420070400000)<<22, 10)
	h.discord.names[young] = "young"
	state, _ := h.start(c, player)
	status, _, page := h.get(c, h.server.URL+"/link/callback?code="+young+"&state="+state)
	if status != 403 || !strings.Contains(page, "too new") || !strings.Contains(page, "30 days") {
		t.Fatalf("%d %s", status, page)
	}
	// not in the Discord server
	state, _ = h.start(c, player)
	status, _, page = h.get(c, h.server.URL+"/link/callback?code=1300000000000000000&state="+state)
	if status != 403 || !strings.Contains(page, "Join the Discord server") || !strings.Contains(page, "https://discord.gg/opence") {
		t.Fatalf("%d %s", status, page)
	}
	// revoked
	if _, err := h.m.RevokeAccount("80351110224678912", "cheating", "admin"); err != nil {
		t.Fatal(err)
	}
	state, _ = h.start(c, player)
	status, _, page = h.get(c, h.server.URL+"/link/callback?code=80351110224678912&state="+state)
	if status != 403 || !strings.Contains(page, "cheating") {
		t.Fatalf("%d %s", status, page)
	}
	if links, _ := h.m.Store.SearchLinks("", 10); len(links) != 0 {
		t.Fatalf("%+v", links)
	}
}

func TestLinkRefusals(t *testing.T) {
	h := newLinkHarness(t, nil)
	c := browser()
	player, _ := sign.NewSeed()
	now := h.m.Now().Unix()
	status, _, page := h.get(c, h.server.URL+"/link?"+sign.SignPlayerQuery(player, sign.LinkLabel, h.m.KeyID, now-601))
	if status != 401 || !strings.Contains(page, "expired") || !strings.Contains(page, "clock") {
		t.Fatalf("%d %s", status, page)
	}
	status, _, page = h.get(c, h.server.URL+"/link?"+sign.SignPlayerQuery(player, sign.LinkLabel, "0123456789abcdef", now))
	if status != 401 || !strings.Contains(page, "not valid") {
		t.Fatalf("%d %s", status, page)
	}
	status, _, _ = h.get(c, h.server.URL+"/link")
	if status != 401 {
		t.Fatal(status)
	}
	// not set up: the page names the fix
	h.pages.Linking = linking{discord.LinkSettings{ClientID: "123456789012345678"}}
	status, _, page = h.get(c, h.server.URL+"/link?"+sign.SignPlayerQuery(player, sign.LinkLabel, h.m.KeyID, now))
	if status != 503 || !strings.Contains(page, "MASTER_DISCORD_CLIENT_SECRET") ||
		!strings.Contains(page, h.server.URL+"/link/callback") {
		t.Fatalf("%d %s", status, page)
	}
	status, _, page = h.get(c, h.server.URL+"/privacy")
	if status != 200 || !strings.Contains(page, "X4BNet") || !strings.Contains(page, "90 days") {
		t.Fatalf("%d %s", status, page)
	}
}

func TestLinkLimited(t *testing.T) {
	h := newLinkHarness(t, nil)
	c := browser()
	statuses := map[int]int{}
	for range web.LinkRate + 2 {
		status, _, _ := h.get(c, h.server.URL+"/link")
		statuses[status]++
	}
	if statuses[429] != 2 {
		t.Fatalf("%v", statuses)
	}
}
