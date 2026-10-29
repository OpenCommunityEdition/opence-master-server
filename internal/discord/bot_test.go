package discord_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/admin"
	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/update"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

const (
	guild     = "100000000000000001"
	channel   = "100000000000000002"
	approvers = "100000000000000003"
	token     = "MTAwMDAwMDAwMDAwMDAwMDAx.Gabcde.secret-token-value_0123456789"
	adminKey  = "admin-token-for-the-discord-tests-0123456789"
)

var (
	applicant = discord.User{ID: "200000000000000001", Name: "milenko"}
	approver  = discord.User{ID: "200000000000000002", Name: "approver"}
	stranger  = discord.User{ID: "200000000000000003", Name: "stranger"}
	owner     = discord.User{ID: "200000000000000004", Name: "owner"}
)

// sent is a message the fake was given: to a channel (or, for a direct
// message, to a user), with its id.
type sent struct {
	To, ID string
	M      discord.Message
}

// fakeDiscord is Discord: a Dialer whose connections record what the bot
// does, and through which a test sends interactions.
type fakeDiscord struct {
	mu     sync.Mutex
	dials  int
	fail   func(token string, n int) error
	conn   *fakeConn
	dialed chan struct{}
}

func (f *fakeDiscord) dial(ctx context.Context, token string, events discord.Events) (discord.Client, error) {
	f.mu.Lock()
	f.dials++
	n := f.dials
	fail := f.fail
	f.mu.Unlock()
	if fail != nil {
		if err := fail(token, n); err != nil {
			return nil, err
		}
	}
	c := &fakeConn{events: events, commands: map[string][]discord.CommandSpec{}}
	f.mu.Lock()
	f.conn = c
	f.mu.Unlock()
	return c, nil
}

func (f *fakeDiscord) current() *fakeConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conn
}

type fakeConn struct {
	events discord.Events

	mu       sync.Mutex
	commands map[string][]discord.CommandSpec
	replies  []discord.Reply
	sent     []sent
	edits    []sent
	dms      []sent
	sendErr  error
	editErr  error
	replyErr error
	closed   bool
	next     int
	// the posts refused with sendErr
	refused int
}

func (c *fakeConn) Self() discord.User {
	return discord.User{ID: "300000000000000001", Name: "OpenCE Master Bot"}
}

func (c *fakeConn) ApplicationID() string { return "300000000000000009" }

func (c *fakeConn) Register(guildID string, commands []discord.CommandSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands[guildID] = commands
	return nil
}

func (c *fakeConn) Reply(i *discord.Interaction, r discord.Reply) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replies = append(c.replies, r)
	return c.replyErr
}

func (c *fakeConn) Send(channelID string, m discord.Message) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendErr != nil {
		c.refused++
		return "", c.sendErr
	}
	c.next++
	id := fmt.Sprintf("40000000000000000%d", c.next)
	c.sent = append(c.sent, sent{To: channelID, ID: id, M: m})
	return id, nil
}

func (c *fakeConn) Edit(channelID, messageID string, m discord.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.editErr != nil {
		return c.editErr
	}
	c.edits = append(c.edits, sent{To: channelID, ID: messageID, M: m})
	return nil
}

func (c *fakeConn) DM(userID string, m discord.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dms = append(c.dms, sent{To: userID, M: m})
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// do sends an interaction and returns the bot's reply to it.
func (c *fakeConn) do(t *testing.T, i *discord.Interaction) discord.Reply {
	t.Helper()
	c.mu.Lock()
	before := len(c.replies)
	c.mu.Unlock()
	c.events.Interaction(c, i)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.replies) != before+1 {
		t.Fatalf("%d replies to %+v", len(c.replies)-before, i)
	}
	return c.replies[len(c.replies)-1]
}

func (c *fakeConn) counts() (sent, edits, dms int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent), len(c.edits), len(c.dms)
}

type harness struct {
	t     *testing.T
	m     *core.Master
	bot   *discord.Bot
	fake  *fakeDiscord
	admin *httptest.Server
	log   *lockedBuffer
}

// lockedBuffer is a log's text, written from any goroutine.
type lockedBuffer struct {
	mu   sync.Mutex
	text strings.Builder
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

func defaults(t *testing.T) *config.Config {
	values := config.Flags(flag.NewFlagSet("test", flag.ContinueOnError))
	for _, o := range config.Options {
		*values[o.Env] = o.Default
	}
	cfg, err := config.Load(values)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name, cfg.Contact, cfg.AdminToken = "Test master", "ops@example.org", adminKey
	cfg.PublicURL = "https://master.example.org"
	return cfg
}

// newHarness makes a master, its bot connected to the fake (with the
// settings set unless configure says otherwise) and its admin pages.
func newHarness(t *testing.T, change func(*config.Config), fail func(string, int) error) *harness {
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
	logged := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m, err := core.New(st, key, cfg, &mail.Notifier{Log: log, Client: http.DefaultClient, Sync: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeDiscord{fail: fail}
	bot := discord.New(m, fake.dial, log)
	bot.Interval, bot.Retry = time.Hour, 10*time.Millisecond
	m.Watcher = bot
	pages, err := admin.New(m, &httpx.Clients{})
	if err != nil {
		t.Fatal(err)
	}
	pages.Discord = bot
	mux := http.NewServeMux()
	pages.Routes(mux)
	public, err := web.New(m, &httpx.Clients{})
	if err != nil {
		t.Fatal(err)
	}
	public.Applying = bot
	public.Routes(mux)
	server := httptest.NewServer(mux)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		server.Close()
		st.Close()
	})
	h := &harness{t: t, m: m, bot: bot, fake: fake, admin: server, log: logged}
	bot.Start(ctx)
	return h
}

// configure saves the bot's settings through the admin pages.
func (h *harness) configure(form url.Values) (int, string) {
	h.t.Helper()
	return h.post("/admin/discord", form)
}

func (h *harness) post(path string, form url.Values) (int, string) {
	h.t.Helper()
	request, _ := http.NewRequest("POST", h.admin.URL+path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer "+adminKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	request, _ := http.NewRequest("GET", h.admin.URL+path, nil)
	request.Header.Set("Authorization", "Bearer "+adminKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func settings() url.Values {
	return url.Values{"token": {token}, "guild": {guild}, "invite": {"https://discord.gg/opence"}}
}

// until waits for a condition (the bot connects on its own goroutine).
func (h *harness) until(what string, ok func() bool) {
	h.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: never (state %+v)", what, h.bot.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// connected sets the settings, waits for the bot's connection, and has a
// server admin choose the log channel and the approver role with
// /configure.
func connected(t *testing.T, change func(*config.Config)) (*harness, *fakeConn) {
	h := newHarness(t, change, nil)
	if status, body := h.configure(settings()); status != 200 {
		t.Fatalf("settings: %d %s", status, body)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	c := h.fake.current()
	c.do(t, configureCommand(owner, "configure"))
	for id, values := range map[string][]string{"config:channel": {channel}, "config:roles": {approvers}} {
		if r := c.do(t, choice(owner, id, values...)); !r.Update || r.Message == nil {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	// (the channel's confirmation)
	c.mu.Lock()
	c.sent = nil
	c.mu.Unlock()
	return h, c
}

func configureCommand(u discord.User, name string) *discord.Interaction {
	return &discord.Interaction{Kind: discord.Command, GuildID: guild, User: u, Admin: u == owner, Name: name}
}

func choice(u discord.User, id string, values ...string) *discord.Interaction {
	return &discord.Interaction{Kind: discord.Select, GuildID: guild, User: u, Admin: u == owner, CustomID: id,
		Selected: values}
}

// command is /apply as u, for 2 servers in eu.
func command(u discord.User, roles ...string) *discord.Interaction {
	return &discord.Interaction{Kind: discord.Command, GuildID: guild, ChannelID: "500000000000000001", User: u,
		Roles: roles, Name: "apply", Options: map[string]string{"region": "eu", "servers": "2"}}
}

func button(u discord.User, id, message string, roles ...string) *discord.Interaction {
	return &discord.Interaction{Kind: discord.Button, GuildID: guild, User: u, Roles: roles, CustomID: id,
		MessageID: message}
}

func modal(u discord.User, id, message string, values map[string]string, roles ...string) *discord.Interaction {
	return &discord.Interaction{Kind: discord.ModalSubmit, GuildID: guild, User: u, Roles: roles, CustomID: id,
		Values: values, MessageID: message}
}

var noncePattern = regexp.MustCompile(`opence-apply-[0-9]+-[0-9a-f]{16}`)

// apply runs /apply, opens the form and sends it, as u, for key; it returns
// the form's reply.
func apply(t *testing.T, c *fakeConn, u discord.User, key ed25519.PrivateKey, edit func(map[string]string)) discord.Reply {
	t.Helper()
	r := c.do(t, command(u))
	if !r.Ephemeral || r.Message == nil || len(r.Message.Buttons) != 1 {
		t.Fatalf("/apply: %+v", r)
	}
	nonce := noncePattern.FindString(r.Message.Content)
	if nonce == "" || !strings.Contains(r.Message.Content, "halo --server --sign "+nonce) ||
		!strings.Contains(r.Message.Content, "halo --server --keygen") {
		t.Fatalf("/apply's text: %s", r.Message.Content)
	}
	form := c.do(t, button(u, r.Message.Buttons[0].ID, ""))
	if form.Modal == nil || len(form.Modal.Inputs) != 4 {
		t.Fatalf("the form: %+v", form)
	}
	values := map[string]string{"name": "Milenko's servers",
		"public_key": sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
		"proof":      hex.EncodeToString(ed25519.Sign(key, []byte(nonce))), "note": "two CTF servers"}
	if edit != nil {
		edit(values)
	}
	return c.do(t, modal(u, form.Modal.ID, "", values))
}

func (h *harness) only(status string) *model.Application {
	h.t.Helper()
	list, err := h.m.Store.Applications(status, 10)
	if err != nil || len(list) != 1 {
		h.t.Fatalf("%d %s applications (%v)", len(list), status, err)
	}
	return &list[0]
}

func fieldsText(m discord.Message) string {
	var parts []string
	for _, e := range m.Embeds {
		parts = append(parts, e.Title, e.URL)
		for _, f := range e.Fields {
			parts = append(parts, f.Name+": "+f.Value)
		}
	}
	return strings.Join(parts, "\n")
}

// The whole application on Discord: /apply's nonce, the form, the
// application stored with its Discord applicant, and its embed posted to
// the log channel with Approve and Deny buttons.
func TestApplyFlow(t *testing.T) {
	h, c := connected(t, nil)
	if got := c.commands[guild]; len(got) != 3 || got[0].Name != "apply" || got[0].AdminOnly ||
		got[1].Name != "configure" || !got[1].AdminOnly || got[2].Name != "config" || !got[2].AdminOnly {
		t.Fatalf("commands registered: %+v", c.commands)
	}
	// /apply's region is a menu of choices, its servers a number Discord checks
	if options := c.commands[guild][0].Options; len(options) != 2 || options[0].Name != "region" ||
		!options[0].Required || len(options[0].Choices) != len(discord.Regions) || options[1].Name != "servers" ||
		!options[1].Integer || options[1].Min != 1 || options[1].Max != 64 {
		t.Fatalf("/apply's options: %+v", options)
	}
	if state := h.bot.State(); state.User.Name != "OpenCE Master Bot" {
		t.Fatalf("state %+v", state)
	}
	key, _ := sign.NewSeed()
	r := apply(t, c, applicant, key, nil)
	if !r.Ephemeral || r.Message == nil || !strings.Contains(r.Message.Content, "received") {
		t.Fatalf("the form's reply: %+v", r)
	}
	a := h.only(model.ApplicationPending)
	if a.DiscordID != applicant.ID || a.Discord != applicant.Name || a.Name != "Milenko's servers" ||
		a.Servers != 2 || a.Region != "eu" || a.Note != "two CTF servers" || !a.ProofOK || a.Email != "" {
		t.Fatalf("stored %+v", a)
	}
	if !strings.Contains(r.Message.Content, a.ID) || !strings.Contains(r.Message.Content, a.KeyID) {
		t.Fatalf("the reply lacks the application: %s", r.Message.Content)
	}
	h.bot.Sync()
	if n, _, _ := c.counts(); n != 1 {
		t.Fatalf("%d messages posted", n)
	}
	post := c.sent[0]
	text := fieldsText(post.M)
	for _, want := range []string{a.ID, "<@" + applicant.ID + ">", a.KeyID, "2, region eu", "Proof of key: verified",
		"Other applications: none", "https://master.example.org/admin/applications/" + a.ID} {
		if !strings.Contains(text, want) {
			t.Errorf("the embed lacks %q:\n%s", want, text)
		}
	}
	if post.To != channel || len(post.M.Buttons) != 2 || post.M.Buttons[0].Label != "Approve" ||
		post.M.Buttons[1].Label != "Deny" {
		t.Fatalf("posted %+v", post)
	}
	stored, _ := h.m.Store.Application(a.ID)
	if stored.LogMessage != post.ID || stored.LogChannel != channel || stored.LogQueued {
		t.Fatalf("the message is not recorded: %+v", stored)
	}
	// nothing more to do
	h.bot.Sync()
	if n, e, d := c.counts(); n != 1 || e != 0 || d != 0 {
		t.Fatalf("%d %d %d", n, e, d)
	}
	// the audit log names the Discord applicant
	entries, _ := h.m.Store.AuditActions("apply", 0, 10)
	if len(entries) != 1 || entries[0].Actor != "discord:"+applicant.ID+" "+applicant.Name {
		t.Fatalf("audit %+v", entries)
	}
	// a second application from the same Discord user shows the first
	other, _ := sign.NewSeed()
	if r := apply(t, c, applicant, other, nil); !strings.Contains(r.Message.Content, "pending") {
		t.Fatalf("a second pending application: %+v", r.Message)
	}
}

// Each refusal of the form, as the applicant sees it, with a button to try
// again (the form filled in with what they sent) where trying again helps.
func TestSubmitRefusals(t *testing.T) {
	h, c := connected(t, func(cfg *config.Config) { cfg.ApplicationsPerDay = 2 })
	key, _ := sign.NewSeed()
	for name, test := range map[string]struct {
		edit  func(map[string]string)
		want  string
		retry bool
	}{
		"name":      {func(v map[string]string) { v["name"] = "ab" }, "Display name", true},
		"key":       {func(v map[string]string) { v["public_key"] = "ed25519:00" }, "Public key", true},
		"proof":     {func(v map[string]string) { v["proof"] = strings.Repeat("00", 64) }, "Proof of key", true},
		"no proof":  {func(v map[string]string) { v["proof"] = "" }, "asks for a proof", true},
		"small key": {func(v map[string]string) { v["public_key"] = "ed25519:" + strings.Repeat("00", 32) }, "Public key", true},
	} {
		r := apply(t, c, applicant, key, test.edit)
		if r.Message == nil || !strings.Contains(r.Message.Content, "not taken") ||
			!strings.Contains(r.Message.Content, test.want) || (len(r.Message.Buttons) == 1) != test.retry {
			t.Errorf("%s: %+v", name, r.Message)
		}
	}
	if n, _ := h.m.Store.CountApplications(model.ApplicationPending); n != 0 {
		t.Fatalf("%d applications taken", n)
	}
	// the next try's form is filled in with the refused one's inputs
	apply(t, c, applicant, key, func(v map[string]string) { v["public_key"] = "ed25519:00" })
	r := c.do(t, command(applicant))
	form := c.do(t, button(applicant, r.Message.Buttons[0].ID, ""))
	if form.Modal.Inputs[0].Value != "Milenko's servers" || form.Modal.Inputs[1].Value != "ed25519:00" ||
		form.Modal.Inputs[3].Value != "two CTF servers" {
		t.Fatalf("the form is not filled in: %+v", form.Modal.Inputs)
	}
	// /apply's options out of range (Discord checks them; the bot again)
	for _, options := range []map[string]string{{"region": "mars", "servers": "2"}, {"region": "eu", "servers": "99"},
		{"region": "eu", "servers": "0"}} {
		in := command(applicant)
		in.Options = options
		if r := c.do(t, in); r.Message == nil || len(r.Message.Buttons) != 0 ||
			!strings.Contains(r.Message.Content, "Choose 1 to 64 servers") {
			t.Errorf("/apply %v: %+v", options, r.Message)
		}
	}
	// a nonce given to another member does not prove this one's key
	r = c.do(t, command(stranger))
	nonce := noncePattern.FindString(r.Message.Content)
	form = c.do(t, button(applicant, r.Message.Buttons[0].ID, ""))
	reply := c.do(t, modal(applicant, form.Modal.ID, "", map[string]string{"name": "Milenko's servers",
		"public_key": sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
		"proof":      hex.EncodeToString(ed25519.Sign(key, []byte(nonce))), "servers": "1"}))
	if !strings.Contains(reply.Message.Content, "not one this master gave you") {
		t.Fatalf("another's nonce: %s", reply.Message.Content)
	}
	// a key that is a publisher's already
	taken, _ := sign.NewSeed()
	nonce = h.m.ProofNonce("")
	a, err := h.m.Apply(core.ApplicationInput{Name: "Taken", Servers: 1,
		PublicKey: sign.PublicKeyText(taken.Public().(ed25519.PublicKey)),
		Proof:     &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(taken, []byte(nonce)))}}, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Approve(a.ID, 0, "cli"); err != nil {
		t.Fatal(err)
	}
	if r := apply(t, c, applicant, taken, nil); !strings.Contains(r.Message.Content, "belongs to a publisher") {
		t.Fatalf("a publisher's key: %s", r.Message.Content)
	}
	// one pending at a time, then the day's limit (2)
	first := apply(t, c, applicant, key, nil)
	if !strings.Contains(first.Message.Content, "received") {
		t.Fatalf("%s", first.Message.Content)
	}
	other, _ := sign.NewSeed()
	if r := apply(t, c, applicant, other, nil); !strings.Contains(r.Message.Content, "is pending") ||
		len(r.Message.Buttons) != 0 {
		t.Fatalf("a second pending: %+v", r.Message)
	}
	if err := h.m.Deny(h.only(model.ApplicationPending).ID, "test", "cli"); err != nil {
		t.Fatal(err)
	}
	if r := apply(t, c, applicant, other, nil); !strings.Contains(r.Message.Content, "received") {
		t.Fatalf("the day's second: %s", r.Message.Content)
	}
	if err := h.m.Deny(h.only(model.ApplicationPending).ID, "test", "cli"); err != nil {
		t.Fatal(err)
	}
	third, _ := sign.NewSeed()
	if r := apply(t, c, applicant, third, nil); !strings.Contains(r.Message.Content, "too many applications from you") ||
		len(r.Message.Buttons) != 0 {
		t.Fatalf("the day's third: %+v", r.Message)
	}
	// from another server
	i := command(applicant)
	i.GuildID = "999999999999999999"
	if r := c.do(t, i); !strings.Contains(r.Message.Content, "own Discord server") {
		t.Fatalf("another server: %s", r.Message.Content)
	}
}

// posted makes an application on Discord and posts it; it returns the
// application and its log channel message.
func posted(t *testing.T, h *harness, c *fakeConn) (*model.Application, sent) {
	t.Helper()
	key, _ := sign.NewSeed()
	apply(t, c, applicant, key, nil)
	h.bot.Sync()
	a := h.only(model.ApplicationPending)
	c.mu.Lock()
	defer c.mu.Unlock()
	return a, c.sent[len(c.sent)-1]
}

// Only an approver may press the buttons; an approval shows its outcome on
// the message at once, and the applicant is told.
func TestApprove(t *testing.T) {
	h, c := connected(t, nil)
	a, post := posted(t, h, c)
	approve, deny := post.M.Buttons[0].ID, post.M.Buttons[1].ID
	for _, id := range []string{approve, deny} {
		r := c.do(t, button(stranger, id, post.ID, "100000000000000099"))
		if !r.Ephemeral || !strings.Contains(r.Message.Content, "Only members with an approver role") {
			t.Fatalf("a member without the role: %+v", r)
		}
	}
	if got, _ := h.m.Store.Application(a.ID); got.Status != model.ApplicationPending {
		t.Fatalf("decided by a stranger: %s", got.Status)
	}
	r := c.do(t, button(approver, approve, post.ID, approvers))
	if !r.Update || r.Message == nil || len(r.Message.Buttons) != 0 {
		t.Fatalf("the approval's reply: %+v", r)
	}
	got, _ := h.m.Store.Application(a.ID)
	if got.Status != model.ApplicationApproved || got.DecidedBy != "discord:"+approver.ID+" approver" ||
		got.LogStatus != model.ApplicationApproved {
		t.Fatalf("%+v", got)
	}
	text := fieldsText(*r.Message)
	if !strings.Contains(text, "Approved: by <@"+approver.ID+">") || !strings.Contains(text, got.PublisherID) {
		t.Fatalf("the embed:\n%s", text)
	}
	state, err := h.m.State(got.PublisherID)
	if err != nil || state.Status != model.Approved || state.Quota != h.m.Config.DefaultQuota {
		t.Fatalf("publisher %v %+v", err, state)
	}
	if p := state.Publisher; p.Discord != applicant.Name || p.DiscordID != applicant.ID || p.Email != "" {
		t.Fatalf("publisher %+v", p)
	}
	entries, _ := h.m.Store.AuditActions("approve", 0, 10)
	if len(entries) != 1 || entries[0].Actor != "discord:"+approver.ID+" approver" || entries[0].Target != a.ID {
		t.Fatalf("audit %+v", entries)
	}
	h.bot.Sync()
	_, edits, dms := c.counts()
	if edits != 0 || dms != 1 || c.dms[0].To != applicant.ID || !strings.Contains(c.dms[0].M.Content, "approved") ||
		!strings.Contains(c.dms[0].M.Content, got.PublisherID) {
		t.Fatalf("%d edits, DMs %+v", edits, c.dms)
	}
	// pressed again: refused, the message left as it is
	r = c.do(t, button(approver, approve, post.ID, approvers))
	if !r.Ephemeral || !strings.Contains(r.Message.Content, "approved already") {
		t.Fatalf("approved twice: %+v", r.Message)
	}
	// with no approver role set (all unchosen on /configure), nobody may
	// decide
	if r = c.do(t, choice(owner, "config:roles")); !strings.Contains(r.Message.Content, "none: nobody may decide") {
		t.Fatalf("the roles not cleared: %+v", r.Message)
	}
	r = c.do(t, button(approver, deny, post.ID, approvers))
	if !strings.Contains(r.Message.Content, "No approver role is set") {
		t.Fatalf("no role set: %+v", r.Message)
	}
}

// Deny opens a form for the reason, then denies with it.
func TestDenyWithReason(t *testing.T) {
	h, c := connected(t, nil)
	a, post := posted(t, h, c)
	r := c.do(t, button(approver, post.M.Buttons[1].ID, post.ID, approvers))
	if r.Modal == nil || len(r.Modal.Inputs) != 1 || !r.Modal.Inputs[0].Required {
		t.Fatalf("the denial's form: %+v", r)
	}
	// a stranger cannot send the form either
	if r := c.do(t, modal(stranger, r.Modal.ID, post.ID, map[string]string{"reason": "x"})); !r.Ephemeral {
		t.Fatalf("a stranger's denial: %+v", r)
	}
	r = c.do(t, modal(approver, r.Modal.ID, post.ID, map[string]string{"reason": "not an operator"}, approvers))
	if !r.Update || len(r.Message.Buttons) != 0 ||
		!strings.Contains(fieldsText(*r.Message), "Denied: by <@"+approver.ID+">") ||
		!strings.Contains(fieldsText(*r.Message), "not an operator") {
		t.Fatalf("the denial's reply: %+v", r)
	}
	got, _ := h.m.Store.Application(a.ID)
	if got.Status != model.ApplicationDenied || got.Reason != "not an operator" {
		t.Fatalf("%+v", got)
	}
	entries, _ := h.m.Store.AuditActions("deny", 0, 10)
	if len(entries) != 1 || entries[0].Detail != "not an operator" ||
		!strings.HasPrefix(entries[0].Actor, "discord:"+approver.ID) {
		t.Fatalf("audit %+v", entries)
	}
	h.bot.Sync()
	if _, _, dms := c.counts(); dms != 1 || !strings.Contains(c.dms[0].M.Content, "not an operator") {
		t.Fatalf("DMs %+v", c.dms)
	}
}

// A decision on the website (or the command line) edits the message: the
// outcome, who decided, no buttons; and the applicant is told.
func TestWebsiteDecisionEditsTheMessage(t *testing.T) {
	h, c := connected(t, nil)
	a, post := posted(t, h, c)
	if status, _ := h.post("/admin/applications/"+a.ID+"/approve", url.Values{}); status != 200 {
		t.Fatalf("the admin's approval: %d", status)
	}
	h.bot.Sync()
	_, edits, dms := c.counts()
	if edits != 1 || dms != 1 {
		t.Fatalf("%d edits, %d DMs", edits, dms)
	}
	edit := c.edits[0]
	if edit.ID != post.ID || edit.To != channel || len(edit.M.Buttons) != 0 ||
		!strings.Contains(fieldsText(edit.M), "Approved: by an admin, on the website") {
		t.Fatalf("the edit: %+v\n%s", edit, fieldsText(edit.M))
	}
	h.bot.Sync()
	if _, edits, dms := c.counts(); edits != 1 || dms != 1 {
		t.Fatal("edited or told twice")
	}
	// a second application, denied on the command line's process (no
	// watcher there): the next synchronisation edits its message too
	h.m.Watcher = nil
	if err := h.m.Deny(a.ID, "x", "cli"); err == nil {
		t.Fatal("an approved application denied")
	}
	key, _ := sign.NewSeed()
	nonce := h.m.ProofNonce("")
	b, err := h.m.Apply(core.ApplicationInput{Name: "From the command line", Servers: 1,
		PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
		Proof:     &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}}, "cli")
	if err != nil {
		t.Fatal(err)
	}
	h.bot.Sync()
	if n, _, _ := c.counts(); n != 2 || !strings.Contains(fieldsText(c.sent[1].M), "added on the command line") {
		t.Fatalf("the command line's application not posted")
	}
	if err := h.m.Deny(b.ID, "a test", "cli"); err != nil {
		t.Fatal(err)
	}
	h.bot.Sync()
	if _, edits, dms := c.counts(); edits != 2 || dms != 1 ||
		!strings.Contains(fieldsText(c.edits[1].M), "Denied: by the command line") {
		t.Fatalf("%d edits, %d DMs", edits, dms)
	}
}

// A failure to post is shown on the page and tried again; a message that
// is gone is given up.
func TestSyncFailures(t *testing.T) {
	h, c := connected(t, nil)
	c.mu.Lock()
	c.sendErr = errors.New("connection reset")
	c.mu.Unlock()
	key, _ := sign.NewSeed()
	apply(t, c, applicant, key, nil)
	h.bot.Sync()
	if state := h.bot.State(); !strings.Contains(state.SyncError, "connection reset") {
		t.Fatalf("state %+v", state)
	}
	if _, page := h.get("/admin/discord"); !strings.Contains(page, "connection reset") {
		t.Fatal("the page does not show the failure")
	}
	c.mu.Lock()
	c.sendErr = nil
	c.editErr = &discord.Error{Status: 404, Message: "Unknown Message"}
	c.mu.Unlock()
	h.bot.Sync()
	if state := h.bot.State(); state.SyncError != "" {
		t.Fatalf("state %+v", state)
	}
	a := h.only(model.ApplicationPending)
	if err := h.m.Deny(a.ID, "x", "admin"); err != nil {
		t.Fatal(err)
	}
	h.bot.Sync()
	if got, _ := h.m.Store.Application(a.ID); got.LogStatus != model.ApplicationDenied {
		t.Fatalf("a deleted message is tried again: %+v", got)
	}
}

// The token is never shown or logged; a refused token is shown on the
// page, and not tried again; a connection that fails is tried again.
func TestTokenAndConnectionErrors(t *testing.T) {
	h := newHarness(t, nil, func(tok string, n int) error {
		if strings.HasPrefix(tok, "bad") {
			return &discord.Error{Status: 401, Message: "Discord refused the bot token (401 Unauthorized)"}
		}
		if n == 2 {
			return errors.New("dial tcp: no route to host " + tok)
		}
		return nil
	})
	if state := h.bot.State(); state.Status != discord.Off || !strings.Contains(state.Reason, "no bot token") {
		t.Fatalf("state %+v", state)
	}
	// a malformed setting is refused
	form := settings()
	form.Set("guild", "my server")
	if _, page := h.configure(form); !strings.Contains(page, "17 to 20 digits") {
		t.Fatalf("a bad guild id taken")
	}
	if status, _ := h.configure(settings()); status != 200 {
		t.Fatal(status)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	_, page := h.get("/admin/discord")
	if strings.Contains(page, token) || !strings.Contains(page, "connected</span> as OpenCE Master Bot") ||
		!strings.Contains(page, "set (leave empty to keep it)") || !strings.Contains(page, guild) ||
		!strings.Contains(page, "client_id=300000000000000009") {
		t.Fatalf("the page:\n%s", page)
	}
	// connect again: the second dial fails, with the token in its error,
	// and is tried again
	if status, _ := h.post("/admin/discord/reconnect", url.Values{}); status != 200 {
		t.Fatal(status)
	}
	h.until("connected again", func() bool {
		h.fake.mu.Lock()
		defer h.fake.mu.Unlock()
		return h.fake.dials >= 3 && h.bot.State().Status == discord.Connected
	})
	// a refused token
	bad := settings()
	bad.Set("token", "bad-token-0123456789-0123456789-abcdef")
	h.configure(bad)
	h.until("refused", func() bool { return h.bot.State().Status == discord.Failed })
	_, page = h.get("/admin/discord")
	if !strings.Contains(page, "Discord refused the bot token (401 Unauthorized)") ||
		strings.Contains(page, "bad-token-0123456789") {
		t.Fatalf("the page:\n%s", page)
	}
	time.Sleep(50 * time.Millisecond)
	h.fake.mu.Lock()
	dials := h.fake.dials
	h.fake.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	h.fake.mu.Lock()
	if h.fake.dials != dials {
		t.Fatal("a refused token is tried again")
	}
	h.fake.mu.Unlock()
	// cleared: off
	if status, _ := h.post("/admin/discord/clear-token", url.Values{}); status != 200 {
		t.Fatal(status)
	}
	if state := h.bot.State(); state.Status != discord.Off {
		t.Fatalf("state %+v", state)
	}
	if s, _ := h.bot.Settings(); s.Token != "" || s.Guild != guild {
		t.Fatalf("settings %+v", s)
	}
	// never in the audit log nor the log
	entries, _ := h.m.Store.AuditLog(100, 0)
	for _, e := range entries {
		if strings.Contains(e.Detail, "secret-token") || strings.Contains(e.Detail, "bad-token") {
			t.Fatalf("the token in the audit log: %+v", e)
		}
	}
	if text := h.log.String(); strings.Contains(text, "secret-token") || strings.Contains(text, "bad-token") {
		t.Fatalf("the token in the log:\n%s", text)
	}
	if !strings.Contains(fmt.Sprint(entries), "token set") || !strings.Contains(fmt.Sprint(entries), "token cleared") {
		t.Fatalf("the token's changes not audited: %+v", entries)
	}
}

// The environment's settings win, and the page cannot change them.
func TestEnvironmentSettings(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.DiscordToken, cfg.DiscordGuild, cfg.DiscordChannel = token, guild, channel
	}, nil)
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	form := settings()
	form.Set("guild", "100000000000000077")
	form.Set("token", "other-token-0123456789-0123456789-abcdef")
	if status, _ := h.configure(form); status != 200 {
		t.Fatal(status)
	}
	s, _ := h.bot.Settings()
	if s.Guild != guild || s.Token != token || s.Channel != channel || !s.FromEnv["guild"] || !s.FromEnv["token"] ||
		!s.FromEnv["channel"] || s.FromEnv["roles"] || len(s.Roles) != 0 {
		t.Fatalf("settings %+v", s)
	}
	// /configure offers the roles only, and refuses the channel
	c := h.fake.current()
	r := c.do(t, configureCommand(owner, "config"))
	if r.Message == nil || len(r.Message.Selects) != 1 || r.Message.Selects[0].ID != "config:roles" ||
		!strings.Contains(r.Message.Content, "MASTER_DISCORD_CHANNEL") {
		t.Fatalf("/config: %+v", r)
	}
	r = c.do(t, choice(owner, "config:channel", "100000000000000077"))
	if s, _ := h.bot.Settings(); s.Channel != channel || !strings.Contains(r.Message.Content, "set by the environment") {
		t.Fatalf("the channel changed: %+v %+v", s, r.Message)
	}
	_, page := h.get("/admin/discord")
	if strings.Contains(page, token) || !strings.Contains(page, "set by MASTER_DISCORD_TOKEN") ||
		!strings.Contains(page, "Set by the environment (MASTER_DISCORD_GUILD)") {
		t.Fatalf("the page:\n%s", page)
	}
	// the public /apply page shows the invite
	response, err := http.Get(h.admin.URL + "/apply")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "https://discord.gg/opence") || !strings.Contains(string(body), "/apply") ||
		strings.Contains(string(body), "<form") {
		t.Fatalf("/apply:\n%s", body)
	}
}

// The Discord page as a browser uses it: a session, its CSRF token, the
// notice after the redirect; the token never on the page, and the form
// refused without the CSRF token.
func TestDiscordPageSession(t *testing.T) {
	h := newHarness(t, nil, nil)
	jar := &cookieJar{}
	client := &http.Client{Jar: jar}
	response, err := client.PostForm(h.admin.URL+"/admin/login", url.Values{"token": {adminKey}})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, response)
	}
	response.Body.Close()
	page := func() string {
		response, err := client.Get(h.admin.URL + "/admin/discord")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body)
	}
	text := page()
	csrf := regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`).FindStringSubmatch(text)
	if csrf == nil || !strings.Contains(text, "no bot token is set") || !strings.Contains(text, "not set") {
		t.Fatalf("the page:\n%s", text)
	}
	form := settings()
	response, _ = client.PostForm(h.admin.URL+"/admin/discord", form)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("saved without the CSRF token: %d", response.StatusCode)
	}
	form.Set("csrf", csrf[1])
	response, err = client.PostForm(h.admin.URL+"/admin/discord", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "Saved; the bot connects again.") || strings.Contains(string(body), token) {
		t.Fatalf("after saving:\n%s", body)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	if text := page(); strings.Contains(text, token) || !strings.Contains(text, "connected</span> as") {
		t.Fatalf("the page:\n%s", text)
	}
}

// cookieJar keeps the session cookie (for a loopback test server).
type cookieJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = append(j.cookies, cookies...)
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies
}

// /configure: for the server's admins only; the channel is taken once the
// bot could post to it; the choices are audited; a new server clears them.
func TestConfigure(t *testing.T) {
	h := newHarness(t, nil, nil)
	// the invite button, before the bot ever connected: the bot user's id,
	// from the token
	if status, _ := h.configure(settings()); status != 200 {
		t.Fatal(status)
	}
	if link := h.bot.AddURL(); !strings.Contains(link, "client_id=100000000000000001") &&
		!strings.Contains(link, "client_id=300000000000000009") {
		t.Fatalf("the link %s", link)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	_, page := h.get("/admin/discord")
	if !strings.Contains(page, "Invite to server") ||
		!strings.Contains(page, "client_id=300000000000000009") || !strings.Contains(page, "guild_id="+guild) ||
		strings.Contains(page, `name="channel"`) || strings.Contains(page, `name="roles"`) ||
		!strings.Contains(page, "none: run <code>/configure</code>") {
		t.Fatalf("the page:\n%s", page)
	}
	c := h.fake.current()
	for _, i := range []*discord.Interaction{configureCommand(stranger, "configure"), configureCommand(stranger, "config"),
		choice(stranger, "config:channel", channel), choice(stranger, "config:roles", approvers)} {
		if r := c.do(t, i); r.Message == nil || !strings.Contains(r.Message.Content, "Only the server's admins") {
			t.Fatalf("%+v: %+v", i, r)
		}
	}
	r := c.do(t, configureCommand(owner, "configure"))
	if !r.Ephemeral || r.Message == nil || len(r.Message.Selects) != 2 ||
		r.Message.Selects[0].Kind != discord.ChannelSelect || r.Message.Selects[1].Kind != discord.RoleSelect {
		t.Fatalf("/configure: %+v", r)
	}
	// a channel the bot cannot post to is not taken
	c.mu.Lock()
	c.sendErr = &discord.Error{Status: 403, Message: "Discord answered 403 Forbidden: Missing Access"}
	c.mu.Unlock()
	r = c.do(t, choice(owner, "config:channel", channel))
	if s, _ := h.bot.Settings(); s.Channel != "" || !strings.Contains(r.Message.Content, "Missing Access") {
		t.Fatalf("taken: %+v %s", s, r.Message.Content)
	}
	c.mu.Lock()
	c.sendErr = nil
	c.mu.Unlock()
	r = c.do(t, choice(owner, "config:channel", channel))
	if s, _ := h.bot.Settings(); s.Channel != channel || !strings.Contains(r.Message.Content, "<#"+channel+">") ||
		r.Message.Selects[0].Defaults[0] != channel {
		t.Fatalf("not taken: %+v %+v", s, r.Message)
	}
	if n, _, _ := c.counts(); n != 1 || c.sent[0].To != channel {
		t.Fatalf("no confirmation in the channel: %+v", c.sent)
	}
	r = c.do(t, choice(owner, "config:roles", approvers, "100000000000000004"))
	if s, _ := h.bot.Settings(); len(s.Roles) != 2 || !strings.Contains(r.Message.Content, "<@&"+approvers+">") {
		t.Fatalf("roles %+v %s", s, r.Message.Content)
	}
	entries, _ := h.m.Store.AuditActions("discord-settings", 0, 10)
	if !strings.Contains(fmt.Sprint(entries), "log channel "+channel) ||
		!strings.Contains(fmt.Sprint(entries), "discord:"+owner.ID) {
		t.Fatalf("not audited: %+v", entries)
	}
	// the approver role decides at once (no reconnection)
	if why := c.do(t, button(stranger, "app:deny:a_x", "", approvers)); strings.Contains(why.Message.Content,
		"approver role") {
		t.Fatalf("the role is not taken: %s", why.Message.Content)
	}
	// a new server clears them
	form := settings()
	form.Set("guild", "100000000000000077")
	h.configure(form)
	if s, _ := h.bot.Settings(); s.Channel != "" || len(s.Roles) != 0 {
		t.Fatalf("kept for a new server: %+v", s)
	}
}

// fakeUpdates is the updater: Start records who started it.
type fakeUpdates struct {
	mu       sync.Mutex
	status   update.Status
	starts   []string
	startErr error
}

func (f *fakeUpdates) Status() update.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeUpdates) Start(actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.starts = append(f.starts, actor)
	f.status.Updating = true
	return nil
}

// The update notice: posted once a release to the log channel; its button
// is the server admins'; it shows the update, and once the master runs the
// release (a new process), says so.
func TestUpdateNotice(t *testing.T) {
	h, c := connected(t, nil)
	updates := &fakeUpdates{status: update.Status{Current: "v1.0.0"}}
	h.bot.Updates = updates
	release := update.Release{Version: "v1.1.0", URL: "https://github.com/x/releases/v1.1.0", Notes: "Faster lists."}
	h.bot.UpdateAvailable(release)
	h.bot.UpdateAvailable(release)
	h.bot.Sync()
	h.bot.Sync()
	if n, _, _ := c.counts(); n != 1 {
		t.Fatalf("%d notices posted", n)
	}
	post := c.sent[0]
	if post.To != channel || len(post.M.Buttons) != 2 || post.M.Buttons[0].Label != "Update now" ||
		post.M.Buttons[1].URL != release.URL || !strings.Contains(post.M.Embeds[0].Description, "Faster lists.") ||
		!strings.Contains(post.M.Embeds[0].Title, "v1.1.0") {
		t.Fatalf("the notice %+v", post)
	}
	press := button(stranger, post.M.Buttons[0].ID, post.ID)
	if r := c.do(t, press); !strings.Contains(r.Message.Content, "Only the server's admins") || len(updates.starts) != 0 {
		t.Fatalf("a stranger updated: %+v", r.Message)
	}
	press = button(owner, post.M.Buttons[0].ID, post.ID)
	press.Admin = true
	h.bot.UpdateStarted("v1.1.0", discord.Actor(owner))
	r := c.do(t, press)
	if !r.Update || len(updates.starts) != 1 || !strings.Contains(r.Message.Embeds[0].Title, "Updating to v1.1.0") ||
		len(r.Message.Buttons) != 1 {
		t.Fatalf("the update's reply: %+v", r.Message)
	}
	// a failure shows, with the button again
	h.bot.UpdateFailed("v1.1.0", errors.New("release v1.1.0's SHA256SUMS is not signed"))
	h.bot.Sync()
	// (the background synchronisation may have shown the update first)
	if _, edits, _ := c.counts(); edits == 0 || !strings.Contains(c.edits[edits-1].M.Embeds[0].Description, "not signed") ||
		c.edits[edits-1].M.Buttons[0].Label != "Try again" {
		t.Fatalf("the failure: %+v", c.edits)
	}
	// started again; then the new process runs the release
	h.bot.UpdateStarted("v1.1.0", discord.Actor(owner))
	h.bot.Sync()
	updates.mu.Lock()
	updates.status = update.Status{Current: "v1.1.0"}
	updates.mu.Unlock()
	h.bot.Sync()
	_, edits, _ := c.counts()
	last := c.edits[edits-1]
	if last.ID != post.ID || !strings.Contains(last.M.Embeds[0].Title, "Updated to v1.1.0") ||
		!strings.Contains(last.M.Embeds[0].Description, "<@"+owner.ID+">") {
		t.Fatalf("the outcome: %+v", last)
	}
	// done: the notice is forgotten
	h.bot.Sync()
	if _, again, _ := c.counts(); again != edits {
		t.Fatal("edited again")
	}
	// a restart into the old version marks the update failed
	updates.mu.Lock()
	updates.status = update.Status{Current: "v1.1.0"}
	updates.mu.Unlock()
	h.bot.UpdateAvailable(update.Release{Version: "v1.2.0"})
	h.bot.UpdateStarted("v1.2.0", "admin")
	h.bot.Sync()
	if n, _, _ := c.counts(); n != 2 || !strings.Contains(fieldsTextOrDescription(c.sent[1].M), "failed") {
		t.Fatalf("not failed: %+v", c.sent)
	}
}

func fieldsTextOrDescription(m discord.Message) string {
	if len(m.Embeds) == 0 {
		return m.Content
	}
	return m.Embeds[0].Title + " " + m.Embeds[0].Description
}

// A stale Approve button (the application denied on the website since) does
// not overturn the denial; nor is a denial's reason past 300 characters
// taken from the website.
func TestStaleApproveAfterDenial(t *testing.T) {
	h, c := connected(t, nil)
	a, post := posted(t, h, c)
	h.post("/admin/applications/"+a.ID+"/deny", url.Values{"reason": {strings.Repeat("x", 301)}})
	if got, _ := h.m.Store.Application(a.ID); got.Status != model.ApplicationPending {
		t.Fatalf("denied with a reason of 301 characters: %+v", got)
	}
	if status, _ := h.post("/admin/applications/"+a.ID+"/deny", url.Values{"reason": {"not an operator"}}); status != 200 {
		t.Fatalf("the admin's denial: %d", status)
	}
	r := c.do(t, button(approver, post.M.Buttons[0].ID, post.ID, approvers))
	if !r.Ephemeral || r.Message == nil || !strings.Contains(r.Message.Content, "Not done") ||
		!strings.Contains(r.Message.Content, "denied") {
		t.Fatalf("the stale approval's reply: %+v", r)
	}
	got, _ := h.m.Store.Application(a.ID)
	records, _ := h.m.Store.KeyRecords(a.KeyID)
	publishers, _ := h.m.Store.Publishers()
	if got.Status != model.ApplicationDenied || got.PublisherID != "" || len(records) != 0 || len(publishers) != 0 {
		t.Fatalf("%+v, keys %+v, publishers %+v", got, records, publishers)
	}
}

// A failure to post holds up neither the edits nor the direct messages; a
// permanent one (the channel gone, or out of the bot's reach) takes the
// application off the queue, as a permanent failure to edit does.
func TestSyncPastAPostFailure(t *testing.T) {
	h, c := connected(t, nil)
	a, _ := posted(t, h, c)
	// (as on the command line's process: no synchronisation but the test's)
	h.m.Watcher = nil
	c.mu.Lock()
	c.sendErr = errors.New("connection reset")
	c.mu.Unlock()
	// (an application older than a's, still to be posted)
	b := &model.Application{ID: "a_older", Name: "n", KeyID: "k", Status: model.ApplicationPending, Created: 1,
		LogQueued: true}
	if err := h.m.Store.CreateApplication(b); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Deny(a.ID, "not an operator", "admin"); err != nil {
		t.Fatal(err)
	}
	h.bot.Sync()
	if _, edits, dms := c.counts(); edits != 1 || dms != 1 {
		t.Fatalf("past a failure to post: %d edits, %d DMs", edits, dms)
	}
	if state := h.bot.State(); !strings.Contains(state.SyncError, "connection reset") {
		t.Fatalf("state %+v", state)
	}
	if got, _ := h.m.Store.Application(b.ID); !got.LogQueued {
		t.Fatalf("taken off the queue for a passing failure: %+v", got)
	}
	// (Discord refusing the message itself, not the channel)
	c.mu.Lock()
	c.sendErr = &discord.Error{Status: 400, Message: "Invalid Form Body"}
	c.mu.Unlock()
	h.bot.Sync()
	if state := h.bot.State(); !strings.Contains(state.SyncError, "Invalid Form Body") {
		t.Fatalf("state %+v", state)
	}
	if got, _ := h.m.Store.Application(b.ID); got.LogQueued || got.LogMessage != "" ||
		got.Status != model.ApplicationPending {
		t.Fatalf("still queued after a permanent failure: %+v", got)
	}
	h.bot.Sync()
	if state := h.bot.State(); state.SyncError != "" {
		t.Fatalf("tried again: %+v", state)
	}
}

// The log channel refusing a post (the bot not allowed to send there yet,
// or the channel gone) keeps the application queued: the posts wait
// PostRetry, and are tried at once after /configure; the applications an
// older version took off the queue after such a refusal are queued again
// when the bot connects, but not those past the hour's number.
func TestSyncChannelRefusal(t *testing.T) {
	h, c := connected(t, nil)
	h.m.Watcher = nil
	before, _, _ := c.counts()
	c.mu.Lock()
	c.sendErr = &discord.Error{Status: 403, Message: "Discord answered 403 Forbidden: Missing Permissions"}
	c.mu.Unlock()
	key, _ := sign.NewSeed()
	apply(t, c, applicant, key, nil)
	h.bot.Sync()
	a := h.only(model.ApplicationPending)
	if got, _ := h.m.Store.Application(a.ID); !got.LogQueued || got.LogMessage != "" {
		t.Fatalf("taken off the queue for the channel's refusal: %+v", got)
	}
	if state := h.bot.State(); !strings.Contains(state.SyncError, "Missing Permissions") ||
		!strings.Contains(state.SyncError, "/configure") {
		t.Fatalf("state %+v", state)
	}
	if _, page := h.get("/admin/discord"); !strings.Contains(page, "Missing Permissions") {
		t.Fatal("the page does not show the refusal")
	}
	// (the permission given in Discord: the post waits for PostRetry)
	c.mu.Lock()
	c.sendErr = nil
	c.mu.Unlock()
	h.bot.Sync()
	if sent, _, _ := c.counts(); sent != before {
		t.Fatalf("posted before PostRetry: %d sent", sent-before)
	}
	if state := h.bot.State(); !strings.Contains(state.SyncError, "Missing Permissions") {
		t.Fatalf("the refusal is not shown while posts wait: %+v", state)
	}
	c.mu.Lock()
	refused := c.refused
	c.mu.Unlock()
	if refused != 1 {
		t.Fatalf("tried again at once: %d refusals", refused)
	}
	// /configure, choosing the channel again: tried at once
	if r := c.do(t, choice(owner, "config:channel", channel)); !r.Update {
		t.Fatalf("%+v", r)
	}
	h.bot.Sync()
	if got, _ := h.m.Store.Application(a.ID); got.LogMessage == "" || got.LogChannel != channel || got.LogQueued {
		t.Fatalf("not posted after /configure: %+v", got)
	}
	if state := h.bot.State(); state.SyncError != "" {
		t.Fatalf("state %+v", state)
	}

	// taken off the queue unposted by an older version, after a refusal;
	// and one past the hour's number (never queued)
	for _, b := range []*model.Application{
		{ID: "a_given_up", Name: "n", KeyID: "k1", Status: model.ApplicationPending, Created: 1,
			LogStatus: model.ApplicationPending},
		{ID: "a_not_announced", Name: "n", KeyID: "k2", Status: model.ApplicationPending, Created: 2},
	} {
		if err := h.m.Store.CreateApplication(b); err != nil {
			t.Fatal(err)
		}
	}
	if status, _ := h.post("/admin/discord/reconnect", url.Values{}); status != 200 {
		t.Fatal(status)
	}
	h.until("connected again", func() bool {
		return h.fake.current() != c && h.bot.State().Status == discord.Connected
	})
	h.bot.Sync()
	if got, _ := h.m.Store.Application("a_given_up"); got.LogMessage == "" {
		t.Fatalf("not queued again: %+v", got)
	}
	if got, _ := h.m.Store.Application("a_not_announced"); got.LogQueued || got.LogMessage != "" {
		t.Fatalf("an application past the hour's number posted: %+v", got)
	}
}

// With no log channel chosen, the applications waiting for one do not hold
// up the edits and direct messages of others, however many they are.
func TestSyncWithoutChannel(t *testing.T) {
	h := newHarness(t, nil, nil)
	if status, body := h.configure(settings()); status != 200 {
		t.Fatalf("settings: %d %s", status, body)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	c := h.fake.current()
	h.m.Watcher = nil
	for i := 0; i < 60; i++ {
		if err := h.m.Store.CreateApplication(&model.Application{ID: fmt.Sprintf("a_queued%d", i), Name: "n",
			KeyID: fmt.Sprintf("k%d", i), DiscordID: fmt.Sprintf("2000000000000001%02d", i),
			Status: model.ApplicationPending, Created: int64(1000 + i), LogQueued: true,
			ToldStatus: model.ApplicationPending}); err != nil {
			t.Fatal(err)
		}
	}
	// posted before the channel was unchosen
	if err := h.m.Store.CreateApplication(&model.Application{ID: "a_posted", Name: "n", KeyID: "kp",
		DiscordID: applicant.ID, Status: model.ApplicationPending, Created: 2000, LogChannel: channel,
		LogMessage: "400000000000000099", LogStatus: model.ApplicationPending,
		ToldStatus: model.ApplicationPending}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Deny("a_posted", "not an operator", "admin"); err != nil {
		t.Fatal(err)
	}
	h.bot.Sync()
	if sent, edits, dms := c.counts(); sent != 0 || edits != 1 || dms != 1 || c.dms[0].To != applicant.ID {
		t.Fatalf("%d posted, %d edits, %d DMs", sent, edits, dms)
	}
	if got, _ := h.m.Store.Application("a_queued59"); !got.LogQueued {
		t.Fatalf("taken off the queue with no channel: %+v", got)
	}
}

// /apply's choices reach the application, and its reply says what was
// chosen; the region is one of the menu's, never none.
func TestApplyOptions(t *testing.T) {
	h, c := connected(t, nil)
	key, _ := sign.NewSeed()
	in := command(applicant)
	in.Options = map[string]string{"region": "na-west", "servers": "1"}
	r := c.do(t, in)
	if !strings.Contains(r.Message.Content, "**1** server at once, in **North America (west)**") {
		t.Fatalf("/apply's text: %s", r.Message.Content)
	}
	nonce := noncePattern.FindString(r.Message.Content)
	form := c.do(t, button(applicant, r.Message.Buttons[0].ID, ""))
	reply := c.do(t, modal(applicant, form.Modal.ID, "", map[string]string{"name": "Milenko's servers",
		"public_key": sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
		"proof":      hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}))
	if !strings.Contains(reply.Message.Content, "received") {
		t.Fatalf("the form's reply: %+v", reply.Message)
	}
	if a := h.only(model.ApplicationPending); a.Servers != 1 || a.Region != "na-west" {
		t.Fatalf("stored %+v", a)
	}
	// the menu: the eight regions, and no "none"
	var values []string
	for _, r := range discord.Regions {
		values = append(values, r.Value)
	}
	if strings.Join(values, ",") != "eu,na-east,na-west,sa,asia,oce,me,africa" {
		t.Fatalf("the regions: %v", values)
	}
	// a region missing, or none of the menu's: refused, with no form
	for _, options := range []map[string]string{{"servers": "2"}, {"region": "", "servers": "2"},
		{"region": "any", "servers": "2"}} {
		in.Options = options
		if r := c.do(t, in); len(r.Message.Buttons) != 0 || !strings.Contains(r.Message.Content, "region from the menu") {
			t.Errorf("/apply %v: %+v", options, r.Message)
		}
	}
}

// The OAuth2 client secret (the player links): set on the Discord page,
// never shown again nor logged nor audited, the environment's winning; the
// client id is the bot's application's.
func TestClientSecret(t *testing.T) {
	h := newHarness(t, nil, nil)
	const secret = "page-client-secret_0123456789abcdef"
	form := settings()
	form.Set("client_secret", secret)
	if status, _ := h.configure(form); status != 200 {
		t.Fatal(status)
	}
	h.until("connected", func() bool { return h.bot.State().Status == discord.Connected })
	link := h.bot.LinkSettings()
	if link.ClientSecret != secret || link.ClientID != "300000000000000009" || link.Guild != guild {
		t.Fatalf("%+v", link)
	}
	_, page := h.get("/admin/discord")
	if strings.Contains(page, secret) || !strings.Contains(page, "A client secret is set") ||
		!strings.Contains(page, "/link/callback") {
		t.Fatalf("the page:\n%s", page)
	}
	bad := settings()
	bad.Set("client_secret", "not a secret!")
	if status, _ := h.configure(bad); status == 200 {
		t.Fatal("a malformed secret taken")
	}
	if status, _ := h.post("/admin/discord/clear-secret", url.Values{}); status != 200 {
		t.Fatal(status)
	}
	if link := h.bot.LinkSettings(); link.ClientSecret != "" {
		t.Fatalf("not cleared: %+v", link)
	}
	entries, _ := h.m.Store.AuditLog(100, 0)
	if !strings.Contains(fmt.Sprint(entries), "client secret set") || !strings.Contains(fmt.Sprint(entries),
		"client secret cleared") || strings.Contains(fmt.Sprint(entries), secret) {
		t.Fatalf("the audit log: %+v", entries)
	}
	if strings.Contains(h.log.String(), secret) {
		t.Fatal("the secret in the log")
	}
	env := newHarness(t, func(cfg *config.Config) {
		cfg.DiscordClientSecret, cfg.DiscordClientID = "env-client-secret_0123456789", "400000000000000001"
	}, nil)
	if link := env.bot.LinkSettings(); link.ClientSecret != "env-client-secret_0123456789" ||
		link.ClientID != "400000000000000001" {
		t.Fatalf("%+v", link)
	}
	if _, page := env.get("/admin/discord"); strings.Contains(page, "env-client-secret") ||
		!strings.Contains(page, "set by MASTER_DISCORD_CLIENT_SECRET") {
		t.Fatalf("the page:\n%s", page)
	}
}
