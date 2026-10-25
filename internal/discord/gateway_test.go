package discord

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bwmarrin/discordgo"
)

// capture answers discordgo's requests without a network, keeping them.
type capture struct {
	mu       sync.Mutex
	requests []captured
	status   int
	answer   string
	// the last request's body
	raw []byte
}

type captured struct {
	method, path string
	body         map[string]any
}

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	var body map[string]any
	var data []byte
	if r.Body != nil {
		data, _ = io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
	}
	c.mu.Lock()
	c.raw = data
	c.requests = append(c.requests, captured{r.Method, r.URL.Path, body})
	status, answer := c.status, c.answer
	c.mu.Unlock()
	if status == 0 {
		status = 200
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Request: r,
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(answer))}, nil
}

func (c *capture) last(t *testing.T) captured {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		t.Fatal("no request")
	}
	return c.requests[len(c.requests)-1]
}

func newGateway(t *testing.T) (*gateway, *capture) {
	s, err := discordgo.New("Bot test-token")
	if err != nil {
		t.Fatal(err)
	}
	c := &capture{answer: `{"id":"900000000000000001"}`}
	s.Client = &http.Client{Transport: c}
	s.MaxRestRetries = 0
	return &gateway{s: s, self: User{ID: "300000000000000001", Name: "bot"}}, c
}

// A modal's submission, as Discord sends it, read into an Interaction.
func TestConvert(t *testing.T) {
	var in discordgo.Interaction
	payload := `{"id":"1","application_id":"3","type":5,"token":"t","guild_id":"100000000000000001",
		"channel_id":"5","member":{"user":{"id":"200000000000000001","username":"milenko"},"roles":["7","8"]},
		"message":{"id":"600000000000000001","channel_id":"5"},
		"data":{"custom_id":"apply:submit:n","components":[
			{"type":1,"components":[{"type":4,"custom_id":"name","value":"Milenko's servers"}]},
			{"type":1,"components":[{"type":4,"custom_id":"servers","value":"2 eu"}]}]}}`
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		t.Fatal(err)
	}
	i := convert(&in)
	if i == nil || i.Kind != ModalSubmit || i.CustomID != "apply:submit:n" || i.User.ID != "200000000000000001" ||
		i.User.Name != "milenko" || strings.Join(i.Roles, ",") != "7,8" || i.MessageID != "600000000000000001" ||
		i.Values["name"] != "Milenko's servers" || i.Values["servers"] != "2 eu" || i.GuildID != "100000000000000001" {
		t.Fatalf("%+v", i)
	}
	payload = `{"id":"1","type":3,"token":"t","guild_id":"1","member":{"user":{"id":"2","username":"a"},"roles":[]},
		"data":{"custom_id":"app:approve:a_1","component_type":2}}`
	in = discordgo.Interaction{}
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		t.Fatal(err)
	}
	if i := convert(&in); i == nil || i.Kind != Button || i.CustomID != "app:approve:a_1" {
		t.Fatalf("%+v", i)
	}
	payload = `{"id":"1","type":2,"token":"t","guild_id":"1","member":{"user":{"id":"2","username":"a"},"roles":[]},
		"data":{"id":"9","name":"apply","type":1}}`
	in = discordgo.Interaction{}
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		t.Fatal(err)
	}
	if i := convert(&in); i == nil || i.Kind != Command || i.Name != "apply" || i.Admin {
		t.Fatalf("%+v", i)
	}
	// a role select menu's choice, by a member with Manage Server
	payload = `{"id":"1","type":3,"token":"t","guild_id":"1",
		"member":{"user":{"id":"2","username":"a"},"roles":[],"permissions":"32"},
		"data":{"custom_id":"config:roles","component_type":6,"values":["7","8"]}}`
	in = discordgo.Interaction{}
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		t.Fatal(err)
	}
	if i := convert(&in); i == nil || i.Kind != Select || i.CustomID != "config:roles" || !i.Admin ||
		strings.Join(i.Selected, ",") != "7,8" {
		t.Fatalf("%+v", i)
	}
}

// What the bot's replies and messages are on the wire.
func TestGatewayRequests(t *testing.T) {
	g, c := newGateway(t)
	in := &discordgo.Interaction{ID: "1", Token: "interaction-token", Type: discordgo.InteractionMessageComponent}
	i := &Interaction{Raw: in}
	if err := g.Reply(i, Reply{Ephemeral: true, Message: &Message{Content: "hello @everyone",
		Buttons: []ButtonSpec{{ID: "apply:form:n", Label: "Fill in", Style: Primary}}}}); err != nil {
		t.Fatal(err)
	}
	r := c.last(t)
	data, _ := r.body["data"].(map[string]any)
	if r.method != "POST" || !strings.HasSuffix(r.path, "/interactions/1/interaction-token/callback") ||
		r.body["type"] != float64(4) || data["flags"] != float64(64) || data["content"] != "hello @everyone" {
		t.Fatalf("%+v", r)
	}
	if mentions, _ := data["allowed_mentions"].(map[string]any); mentions == nil || len(mentions["parse"].([]any)) != 0 {
		t.Fatalf("mentions allowed: %+v", data)
	}
	rows := data["components"].([]any)
	button := rows[0].(map[string]any)["components"].([]any)[0].(map[string]any)
	if button["custom_id"] != "apply:form:n" || button["style"] != float64(1) {
		t.Fatalf("%+v", button)
	}
	if err := g.Reply(i, Reply{Modal: &Modal{ID: "apply:submit:n", Title: "Apply", Inputs: []Input{
		{ID: "name", Label: "Name", Required: true, Min: 3, Max: 32}, {ID: "note", Label: "Note", Long: true}}}}); err != nil {
		t.Fatal(err)
	}
	r = c.last(t)
	data = r.body["data"].(map[string]any)
	inputs := data["components"].([]any)
	second := inputs[1].(map[string]any)["components"].([]any)[0].(map[string]any)
	if r.body["type"] != float64(9) || data["custom_id"] != "apply:submit:n" || len(inputs) != 2 ||
		second["style"] != float64(2) {
		t.Fatalf("%+v", r.body)
	}
	if err := g.Reply(i, Reply{Update: true, Message: &Message{Embeds: []Embed{{Title: "Application a_1"}}}}); err != nil {
		t.Fatal(err)
	}
	r = c.last(t)
	data = r.body["data"].(map[string]any)
	if r.body["type"] != float64(7) || len(data["components"].([]any)) != 0 {
		t.Fatalf("an update keeps the buttons: %+v", r.body)
	}
	id, err := g.Send("100000000000000002", Message{Embeds: []Embed{{Title: "Application a_1",
		Fields: []Field{{Name: "Name", Value: "x", Inline: true}}}}, Buttons: []ButtonSpec{
		{ID: "app:approve:a_1", Label: "Approve", Style: Success}, {ID: "app:deny:a_1", Label: "Deny", Style: Danger}}})
	r = c.last(t)
	if err != nil || id != "900000000000000001" || !strings.HasSuffix(r.path, "/channels/100000000000000002/messages") {
		t.Fatalf("%v %s %+v", err, id, r)
	}
	if err := g.Edit("100000000000000002", "900000000000000001", Message{Embeds: []Embed{{Title: "x"}}}); err != nil {
		t.Fatal(err)
	}
	r = c.last(t)
	if r.method != "PATCH" || !strings.HasSuffix(r.path, "/messages/900000000000000001") ||
		len(r.body["components"].([]any)) != 0 {
		t.Fatalf("an edit keeps the buttons: %+v", r)
	}
	// select menus, a row each before the buttons
	if err := g.Reply(i, Reply{Ephemeral: true, Message: &Message{Content: "configure", Selects: []SelectSpec{
		{ID: "config:channel", Kind: ChannelSelect, Min: 1, Max: 1, Defaults: []string{"100000000000000002"}},
		{ID: "config:roles", Kind: RoleSelect, Max: 10}}}}); err != nil {
		t.Fatal(err)
	}
	rows = c.last(t).body["data"].(map[string]any)["components"].([]any)
	first := rows[0].(map[string]any)["components"].([]any)[0].(map[string]any)
	roles := rows[1].(map[string]any)["components"].([]any)[0].(map[string]any)
	if len(rows) != 2 || first["type"] != float64(8) || first["min_values"] != float64(1) ||
		fmt.Sprint(first["default_values"]) != "[map[id:100000000000000002 type:channel]]" ||
		fmt.Sprint(first["channel_types"]) != "[0]" || roles["type"] != float64(6) ||
		roles["min_values"] != float64(0) || roles["max_values"] != float64(10) {
		t.Fatalf("%+v", rows)
	}
	// /configure is the admins'
	c.mu.Lock()
	c.answer = `[]`
	c.mu.Unlock()
	if err := g.Register("100000000000000001", []CommandSpec{{Name: "apply", Description: "a"},
		{Name: "configure", Description: "c", AdminOnly: true}}); err != nil {
		t.Fatal(err)
	}
	var commands []map[string]any
	c.mu.Lock()
	raw := c.raw
	c.mu.Unlock()
	if err := json.Unmarshal(raw, &commands); err != nil || len(commands) != 2 ||
		commands[0]["default_member_permissions"] != nil || commands[1]["default_member_permissions"] != "32" {
		t.Fatalf("%v %s", err, raw)
	}
	c.mu.Lock()
	c.answer = `{"id":"900000000000000001"}`
	c.mu.Unlock()
	// Discord's refusal is an *Error, permanent but for 429
	c.mu.Lock()
	c.status, c.answer = 404, `{"code":10008,"message":"Unknown Message"}`
	c.mu.Unlock()
	err = g.Edit("1", "2", Message{})
	var e *Error
	if !Permanent(err) || !strings.Contains(err.Error(), "Unknown Message") || !asError(err, &e) || e.Status != 404 {
		t.Fatalf("%v", err)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	*target = e
	return ok
}

// discordgo's log lines (its debug lines hold the identify packet) never
// carry a session's token.
func TestRedact(t *testing.T) {
	logToken("secret-token", true)
	defer logToken("secret-token", false)
	var text strings.Builder
	logMu.Lock()
	old := logSink
	logSink = slog.New(slog.NewTextHandler(&text, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logMu.Unlock()
	defer func() {
		logMu.Lock()
		logSink = old
		logMu.Unlock()
	}()
	discordLog(discordgo.LogError, 1, "identify {token:%s}", "secret-token")
	if strings.Contains(text.String(), "secret-token") || !strings.Contains(text.String(), "<token>") {
		t.Fatal(text.String())
	}
	if got := redact("a secret-token b", "secret-token"); got != "a <token> b" {
		t.Fatal(got)
	}
}
