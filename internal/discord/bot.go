package discord

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
)

// The settings' keys in the database.
const (
	keyToken   = "discord.token"
	keyGuild   = "discord.guild"
	keyChannel = "discord.channel"
	keyRoles   = "discord.roles"
	keyInvite  = "discord.invite"
)

// MaximumRoles is how many approver roles may be set.
const MaximumRoles = 10

// Permissions is what the bot needs in the log channel: View Channel, Send
// Messages and Embed Links.
const Permissions = 1024 | 2048 | 16384

var (
	snowflakePattern = regexp.MustCompile(`^[0-9]{17,20}$`)
	tokenPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{30,200}$`)
)

// Settings are the bot's settings: the admin page's and /configure's (in
// the database), each replaced by its MASTER_DISCORD_* variable when that is
// set.
type Settings struct {
	Token   string
	Guild   string
	Channel string
	Roles   []string
	Invite  string
	// the settings the environment sets: "token", "guild", "channel",
	// "roles", "invite"
	FromEnv map[string]bool
}

// Form is what the admin page sends. An empty Token keeps the stored one.
// (The log channel and the approver roles are chosen on Discord, with
// /configure.)
type Form struct {
	Token, Guild, Invite string
	ClearToken           bool
}

// Status is the bot's connection.
type Status string

// The connection's states.
const (
	Off        Status = "off"
	Connecting Status = "connecting"
	Connected  Status = "connected"
	Failed     Status = "error"
)

// State is what the admin page shows of the bot.
type State struct {
	Status Status
	// why it is off, or the error
	Reason string
	// the bot's user and application, once connected
	User          User
	ApplicationID string
	Since         time.Time
	// the last synchronisation's failures to post or edit a log channel
	// message, or to tell an applicant (none once a pass succeeds)
	SyncError string
}

// Bot is the Discord bot.
type Bot struct {
	M    *core.Master
	Dial Dialer
	Log  *slog.Logger
	// how often the applications are synchronised with Discord, besides at
	// each change made in this process
	Interval time.Duration
	// the first wait before connecting again after a failure (doubled each
	// time, to 10 minutes)
	Retry time.Duration

	mu       sync.Mutex
	ctx      context.Context
	settings Settings
	client   Client
	state    State
	// each connection's number: the events of an older one are ignored
	generation uint64
	stop       context.CancelFunc
	drafts     map[string]draft
	// the applications an approver is deciding on Discord: their message is
	// updated by the reply, not edited by Sync
	deciding map[string]bool
	kick     chan struct{}
	syncing  sync.Mutex
	// the master's updates, which the log channel's notice starts (nil:
	// none)
	Updates Updates
}

// draft is a modal's inputs kept after a refusal, to fill the next try in.
type draft struct {
	values map[string]string
	at     time.Time
}

// New makes the bot; Start connects it.
func New(m *core.Master, dial Dialer, log *slog.Logger) *Bot {
	return &Bot{M: m, Dial: dial, Log: log, Interval: 15 * time.Second, Retry: 15 * time.Second,
		state: State{Status: Off, Reason: "not started"}, drafts: map[string]draft{}, deciding: map[string]bool{},
		kick: make(chan struct{}, 1)}
}

// Settings returns the bot's settings.
func (b *Bot) Settings() (Settings, error) {
	s := Settings{FromEnv: map[string]bool{}}
	stored := map[string]*string{keyToken: &s.Token, keyGuild: &s.Guild, keyChannel: &s.Channel, keyInvite: &s.Invite}
	var roles string
	stored[keyRoles] = &roles
	for key, target := range stored {
		value, _, err := b.M.Store.Setting(key)
		if err != nil {
			return s, err
		}
		*target = value
	}
	cfg := b.M.Config
	for name, env := range map[string]struct {
		value  string
		target *string
	}{"token": {cfg.DiscordToken, &s.Token}, "guild": {cfg.DiscordGuild, &s.Guild},
		"channel": {cfg.DiscordChannel, &s.Channel}, "roles": {cfg.DiscordRoles, &roles},
		"invite": {cfg.DiscordInvite, &s.Invite}} {
		if env.value != "" {
			*env.target = env.value
			s.FromEnv[name] = true
		}
	}
	s.Roles = splitRoles(roles)
	return s, nil
}

func splitRoles(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// CheckEnvironment checks the MASTER_DISCORD_* variables, for serve to
// refuse bad ones at its start.
func CheckEnvironment(cfg *config.Config) error {
	_, err := checkForm(Form{Token: cfg.DiscordToken, Guild: cfg.DiscordGuild, Invite: cfg.DiscordInvite})
	if err == nil {
		err = checkChannel(cfg.DiscordChannel)
	}
	if err == nil {
		err = checkRoles(splitRoles(cfg.DiscordRoles))
	}
	if err != nil {
		return fmt.Errorf("MASTER_DISCORD_*: %w", err)
	}
	return nil
}

func checkChannel(id string) error {
	if id = strings.TrimSpace(id); id != "" && !snowflakePattern.MatchString(id) {
		return errors.New("the log channel id is a Discord id: 17 to 20 digits (Developer Mode, Copy ID)")
	}
	return nil
}

func checkRoles(roles []string) error {
	if len(roles) > MaximumRoles {
		return fmt.Errorf("%d approver roles at most", MaximumRoles)
	}
	for _, r := range roles {
		if !snowflakePattern.MatchString(r) {
			return fmt.Errorf("%q is not a role id: 17 to 20 digits", r)
		}
	}
	return nil
}

// checkForm checks a form's values, returning the token as stored (without
// a "Bot " prefix pasted with it).
func checkForm(f Form) (string, error) {
	var errs []error
	token := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f.Token), "Bot "))
	if token != "" && !tokenPattern.MatchString(token) {
		errs = append(errs, errors.New("the bot token is the Developer Portal's token (letters, digits, '.', '_' and '-')"))
	}
	if id := strings.TrimSpace(f.Guild); id != "" && !snowflakePattern.MatchString(id) {
		errs = append(errs, errors.New("the server id is a Discord id: 17 to 20 digits (Developer Mode, Copy ID)"))
	}
	if invite := strings.TrimSpace(f.Invite); invite != "" {
		u, err := url.Parse(invite)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(invite) > 200 || !core.Printable(invite) {
			errs = append(errs, errors.New("the invite is an https:// URL of 200 characters at most"))
		}
	}
	return token, errors.Join(errs...)
}

// Save stores the admin page's settings (those the environment does not
// set), writes what changed to the audit log (never the token), and
// connects the bot again. A new server clears the log channel and the
// approver roles, which were the old server's.
func (b *Bot) Save(f Form, actor string) error {
	token, err := checkForm(f)
	if err != nil {
		return &core.ActionError{Code: "schema", Message: err.Error()}
	}
	current, err := b.Settings()
	if err != nil {
		return err
	}
	var changes []string
	set := func(name, key, value, label string) error {
		if current.FromEnv[name] {
			return nil
		}
		old, _, err := b.M.Store.Setting(key)
		if err != nil || old == value {
			return err
		}
		if err := b.M.Store.SetSetting(key, value); err != nil {
			return err
		}
		if value == "" {
			changes = append(changes, label+" cleared")
		} else {
			changes = append(changes, label+" "+value)
		}
		return nil
	}
	if guild := strings.TrimSpace(f.Guild); !current.FromEnv["guild"] && guild != current.Guild {
		if err := set("guild", keyGuild, guild, "server"); err != nil {
			return err
		}
		if err := set("channel", keyChannel, "", "log channel"); err != nil {
			return err
		}
		if err := set("roles", keyRoles, "", "approver roles"); err != nil {
			return err
		}
	}
	if err := set("invite", keyInvite, strings.TrimSpace(f.Invite), "invite"); err != nil {
		return err
	}
	if !current.FromEnv["token"] {
		switch {
		case f.ClearToken:
			if err := b.M.Store.SetSetting(keyToken, ""); err != nil {
				return err
			}
			changes = append(changes, "token cleared")
		case token != "":
			if err := b.M.Store.SetSetting(keyToken, token); err != nil {
				return err
			}
			changes = append(changes, "token set")
		}
	}
	detail := "unchanged"
	if len(changes) > 0 {
		detail = strings.Join(changes, ", ")
	}
	_ = b.M.Store.Audit(actor, "discord-settings", "", detail)
	b.Restart()
	return nil
}

// SetChannel sets the log channel (for /configure), writes it to the audit
// log, and posts the waiting applications there.
func (b *Bot) SetChannel(channel, actor string) error {
	return b.configure("channel", keyChannel, channel, "log channel", actor, func(s *Settings) {
		s.Channel = channel
	})
}

// SetRoles sets the approver roles (for /configure) and writes them to the
// audit log.
func (b *Bot) SetRoles(roles []string, actor string) error {
	return b.configure("roles", keyRoles, strings.Join(roles, ","), "approver roles", actor, func(s *Settings) {
		s.Roles = roles
	})
}

func (b *Bot) configure(name, key, value, label, actor string, apply func(*Settings)) error {
	current, err := b.Settings()
	if err != nil {
		return err
	}
	if current.FromEnv[name] {
		return &core.ActionError{Code: "environment", Message: "the " + label + " is set by the environment"}
	}
	if err := b.M.Store.SetSetting(key, value); err != nil {
		return err
	}
	detail := label + " " + value
	if value == "" {
		detail = label + " cleared"
	}
	_ = b.M.Store.Audit(actor, "discord-settings", "", detail)
	b.mu.Lock()
	apply(&b.settings)
	b.mu.Unlock()
	b.ApplicationChanged("")
	return nil
}

// State returns the bot's state.
func (b *Bot) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Accepting tells whether the bot is connected (and takes applications).
func (b *Bot) Accepting() bool { return b.State().Status == Connected }

// InviteURL is the invite to the Discord server the /apply page shows.
func (b *Bot) InviteURL() string {
	s, err := b.Settings()
	if err != nil {
		return ""
	}
	return s.Invite
}

// AddURL is the link that adds the bot to its server, with the scopes and
// permissions it needs (empty without a token).
func (b *Bot) AddURL() string {
	b.mu.Lock()
	id, s := b.state.ApplicationID, b.settings
	b.mu.Unlock()
	if id == "" {
		// (before Discord has said: the bot user's id, which is the
		// application's for most bots)
		id = tokenUser(s.Token)
	}
	if id == "" {
		return ""
	}
	link := fmt.Sprintf("https://discord.com/oauth2/authorize?client_id=%s&scope=bot+applications.commands"+
		"&permissions=%d", id, Permissions)
	if s.Guild != "" {
		link += "&guild_id=" + s.Guild + "&disable_guild_select=true"
	}
	return link
}

// tokenUser is the bot user's id a token starts with (empty if it is not a
// bot token).
func tokenUser(token string) string {
	first, _, _ := strings.Cut(token, ".")
	id, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(first, "="))
	if err != nil || !snowflakePattern.Match(id) {
		return ""
	}
	return string(id)
}

func (b *Bot) setState(generation uint64, change func(*State)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if generation != b.generation {
		return
	}
	previous := b.state.Status
	change(&b.state)
	if b.state.Status != previous {
		b.state.Since = b.M.Now()
	}
}

// Start connects the bot (when its settings allow) and synchronises the
// applications with Discord until ctx ends.
func (b *Bot) Start(ctx context.Context) {
	b.mu.Lock()
	b.ctx = ctx
	b.mu.Unlock()
	b.Restart()
	go func() {
		ticker := time.NewTicker(b.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				b.mu.Lock()
				if b.stop != nil {
					b.stop()
				}
				old := b.client
				b.client = nil
				b.mu.Unlock()
				if old != nil {
					_ = old.Close()
				}
				return
			case <-ticker.C:
			case <-b.kick:
			}
			b.Sync()
		}
	}()
}

// Restart drops the connection and connects again with the stored
// settings.
func (b *Bot) Restart() {
	b.mu.Lock()
	if b.ctx == nil {
		b.mu.Unlock()
		return
	}
	if b.stop != nil {
		b.stop()
		b.stop = nil
	}
	old := b.client
	b.client = nil
	b.generation++
	generation := b.generation
	settings, err := b.Settings()
	b.settings = settings
	b.state = State{Status: Off, Since: b.M.Now()}
	switch {
	case err != nil:
		b.state = State{Status: Failed, Reason: "the settings could not be read: " + err.Error(), Since: b.M.Now()}
	case settings.Token == "":
		b.state.Reason = "no bot token is set"
	case settings.Guild == "":
		b.state.Reason = "no server id is set"
	default:
		b.state.Status = Connecting
		ctx, stop := context.WithCancel(b.ctx)
		b.stop = stop
		go b.connect(ctx, generation, settings)
	}
	state := b.state
	b.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if state.Status != Connecting {
		b.Log.Info("discord: the bot is off", "reason", state.Reason)
	}
}

// redact takes a token out of a text (an error's).
func redact(text, token string) string {
	if token == "" {
		return text
	}
	return strings.ReplaceAll(text, token, "<token>")
}

func (b *Bot) connect(ctx context.Context, generation uint64, s Settings) {
	wait := b.Retry
	events := Events{
		Interaction: func(c Client, i *Interaction) { b.handle(generation, c, i) },
		Disconnected: func() {
			b.setState(generation, func(st *State) { st.Status, st.Reason = Connecting, "reconnecting" })
		},
		Connected: func() {
			b.setState(generation, func(st *State) {
				if st.User.ID != "" {
					st.Status, st.Reason = Connected, ""
				}
			})
		},
	}
	for {
		appID := ""
		client, err := b.Dial(ctx, s.Token, events)
		if err == nil {
			err = client.Register(s.Guild, b.commands())
			if err != nil {
				// (kept for the link that adds the bot to the server)
				appID = client.ApplicationID()
				_ = client.Close()
				err = fmt.Errorf("the /apply command could not be registered in server %s (is the bot added to it "+
					"with the applications.commands scope?): %w", s.Guild, err)
			}
		}
		if ctx.Err() != nil {
			if client != nil && err == nil {
				_ = client.Close()
			}
			return
		}
		if err == nil {
			b.mu.Lock()
			if generation != b.generation {
				b.mu.Unlock()
				_ = client.Close()
				return
			}
			b.client = client
			b.state = State{Status: Connected, User: client.Self(), ApplicationID: client.ApplicationID(),
				Since: b.M.Now()}
			b.mu.Unlock()
			b.Log.Info("discord: connected", "bot", client.Self().Name)
			b.ApplicationChanged("")
			return
		}
		reason := redact(err.Error(), s.Token)
		permanent := Permanent(err)
		if !permanent {
			reason += fmt.Sprintf("; trying again in %s", wait)
		}
		b.Log.Warn("discord: not connected", "err", reason)
		b.setState(generation, func(st *State) {
			st.Status, st.Reason = Failed, reason
			if appID != "" {
				st.ApplicationID = appID
			}
		})
		if permanent {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		b.setState(generation, func(st *State) { st.Status = Connecting })
		if wait *= 2; wait > 10*time.Minute {
			wait = 10 * time.Minute
		}
	}
}

// commands are the slash commands the bot registers in its server.
func (b *Bot) commands() []CommandSpec {
	configure := "Choose the channel the applications are posted to, and the roles that decide them"
	return []CommandSpec{
		{Name: "apply", Description: "Apply to publish OpenCE dedicated servers on " + b.M.Name()},
		{Name: "configure", Description: configure, AdminOnly: true},
		{Name: "config", Description: configure, AdminOnly: true},
	}
}

// current returns the connected client and the settings, if the
// generation's connection is the current one.
func (b *Bot) current(generation uint64) (Client, Settings, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.client, b.settings, generation == b.generation
}

// ApplicationChanged is core.Watcher's: an application made or decided is
// synchronised with Discord at once.
func (b *Bot) ApplicationChanged(string) {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// Alert is core.Watcher's: an alert for the admins, posted to the log
// channel.
func (b *Bot) Alert(text string) {
	b.mu.Lock()
	client, channel := b.client, b.settings.Channel
	b.mu.Unlock()
	if client == nil || channel == "" {
		return
	}
	go func() {
		if _, err := client.Send(channel, Message{Content: text}); err != nil {
			b.Log.Warn("discord: the alert was not posted", "err", err)
		}
	}()
}

// TellAge is how long after a decision its Discord applicant is still told
// of it: decisions older than that (made while the bot was off) are not
// sent.
const TellAge = 7 * 24 * time.Hour

// Sync brings Discord in line with the applications: posts the new ones to
// the log channel, edits the messages of those decided since, and tells
// Discord applicants of decisions. Each kind of work is read and done on its
// own, so that one that fails does not hold up the others: a failure to post
// stops the posts for the pass (a permanent one, the channel gone or out of
// the bot's reach, takes that application off the queue), one to edit stops
// the edits, to be tried again at the next pass.
func (b *Bot) Sync() {
	b.syncing.Lock()
	defer b.syncing.Unlock()
	b.mu.Lock()
	client, settings, generation := b.client, b.settings, b.generation
	b.mu.Unlock()
	if client == nil {
		return
	}
	var failures []string
	fail := func(failure string) {
		if failure != "" {
			failures = append(failures, failure)
		}
	}
	fail(b.syncPosts(client, settings))
	fail(b.syncEdits(client))
	fail(b.syncTold(client))
	fail(b.syncUpdate(client, settings))
	b.setState(generation, func(st *State) { st.SyncError = strings.Join(failures, "; ") })
}

// syncBatch is how many applications of each kind a pass reads.
const syncBatch = 50

func (b *Bot) syncPosts(client Client, s Settings) string {
	// (decided before they were posted: not posted)
	if err := b.M.Store.UnqueueDecided(); err != nil {
		return "applications not read: " + err.Error()
	}
	if s.Channel == "" {
		// (posted once a channel is chosen)
		return ""
	}
	list, err := b.M.Store.ApplicationsToPost(syncBatch)
	if err != nil {
		return "applications not read: " + err.Error()
	}
	for i := range list {
		a := &list[i]
		id, err := client.Send(s.Channel, b.applicationMessage(a))
		if err != nil && Permanent(err) {
			b.Log.Warn("discord: application not posted, for good", "id", a.ID, "err", err)
			if err := b.M.Store.SetApplicationPosted(a.ID, "", "", a.Status); err != nil {
				return err.Error()
			}
			return fmt.Sprintf("application %s not posted to channel %s, and not tried again: %v", a.ID,
				s.Channel, err)
		} else if err != nil {
			b.Log.Warn("discord: application not posted", "id", a.ID, "err", err)
			return fmt.Sprintf("application %s not posted to channel %s: %v", a.ID, s.Channel, err)
		}
		if err := b.M.Store.SetApplicationPosted(a.ID, s.Channel, id, a.Status); err != nil {
			return err.Error()
		}
	}
	return ""
}

func (b *Bot) syncEdits(client Client) string {
	list, err := b.M.Store.ApplicationsToEdit(syncBatch)
	if err != nil {
		return "applications not read: " + err.Error()
	}
	for i := range list {
		a := &list[i]
		b.mu.Lock()
		deciding := b.deciding[a.ID]
		b.mu.Unlock()
		if deciding {
			continue
		}
		if err := client.Edit(a.LogChannel, a.LogMessage, b.applicationMessage(a)); err != nil && !Permanent(err) {
			b.Log.Warn("discord: application message not edited", "id", a.ID, "err", err)
			return fmt.Sprintf("the message of application %s not edited: %v", a.ID, err)
		} else if err != nil {
			// (the message was deleted, or the channel is gone)
			b.Log.Info("discord: application message not edited, for good", "id", a.ID, "err", err)
		}
		if err := b.M.Store.SetApplicationShown(a.ID, a.Status); err != nil {
			return err.Error()
		}
	}
	return ""
}

func (b *Bot) syncTold(client Client) string {
	list, err := b.M.Store.ApplicationsToTell(syncBatch)
	if err != nil {
		return "applications not read: " + err.Error()
	}
	for i := range list {
		a := &list[i]
		if b.M.Now().Unix()-a.Updated <= int64(TellAge/time.Second) {
			if err := client.DM(a.DiscordID, b.decisionMessage(a)); err != nil {
				// (best effort: the applicant may take no direct messages)
				b.Log.Info("discord: applicant not told", "id", a.ID, "err", err)
			}
		}
		if err := b.M.Store.SetApplicationTold(a.ID, a.Status); err != nil {
			return err.Error()
		}
	}
	return ""
}
