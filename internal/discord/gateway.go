package discord

// This file is the only one that talks to Discord: through discordgo
// (github.com/bwmarrin/discordgo, BSD-3-Clause), over the gateway (an
// outgoing WebSocket: the master needs no public URL for it) and Discord's
// REST API.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gorilla/websocket"
)

// ReadyTimeout bounds the wait for Discord's READY after connecting.
const ReadyTimeout = 30 * time.Second

var (
	// the tokens of the sessions open, taken out of discordgo's log lines
	logMu     sync.Mutex
	logTokens = map[string]int{}
	logSink   *slog.Logger
)

func logToken(token string, add bool) {
	logMu.Lock()
	defer logMu.Unlock()
	if add {
		logTokens[token]++
	} else if logTokens[token]--; logTokens[token] <= 0 {
		delete(logTokens, token)
	}
}

// discordLog writes discordgo's warnings and errors to the master's log,
// without a token in them.
func discordLog(level, caller int, format string, a ...any) {
	text := fmt.Sprintf(format, a...)
	logMu.Lock()
	for token := range logTokens {
		text = strings.ReplaceAll(text, token, "<token>")
	}
	sink := logSink
	logMu.Unlock()
	if sink == nil {
		return
	}
	if level == discordgo.LogError {
		sink.Warn("discord: " + text)
	} else {
		sink.Debug("discord: " + text)
	}
}

// Gateway is the Dialer of Discord itself.
func Gateway(log *slog.Logger) Dialer {
	logMu.Lock()
	logSink = log
	logMu.Unlock()
	discordgo.Logger = discordLog
	return dial
}

// describe makes a library's error an *Error where Discord refused.
func describe(err error) error {
	var rest *discordgo.RESTError
	if errors.As(err, &rest) && rest.Response != nil {
		message := rest.Response.Status
		if rest.Message != nil && rest.Message.Message != "" {
			message += ": " + rest.Message.Message
		}
		return &Error{Status: rest.Response.StatusCode, Message: "Discord answered " + message}
	}
	var closed *websocket.CloseError
	if errors.As(err, &closed) {
		message := fmt.Sprintf("Discord closed the gateway (%d %s)", closed.Code, closed.Text)
		if closed.Code == 4004 {
			message = "Discord refused the bot token (gateway 4004 Authentication failed)"
		}
		return &Error{Status: closed.Code, Message: message}
	}
	return err
}

func dial(ctx context.Context, token string, events Events) (Client, error) {
	s, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}
	// (interactions need no gateway intent; the members' roles come with
	// each interaction, so no privileged intent either)
	s.Identify.Intents = discordgo.IntentsNone
	s.StateEnabled = false
	s.LogLevel = discordgo.LogError
	s.Client = &http.Client{Timeout: 20 * time.Second}
	me, err := s.User("@me", discordgo.WithContext(ctx))
	if err != nil {
		err = describe(err)
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusUnauthorized {
			e.Message = "Discord refused the bot token (401 Unauthorized): copy it again from the Developer " +
				"Portal (Bot, Reset Token)"
		}
		return nil, err
	}
	logToken(token, true)
	g := &gateway{s: s, self: User{ID: me.ID, Name: me.Username}, token: token}
	ready := make(chan struct{}, 1)
	s.AddHandler(func(_ *discordgo.Session, r *discordgo.Ready) {
		if r.Application != nil && r.Application.ID != "" {
			g.mu.Lock()
			g.appID = r.Application.ID
			g.mu.Unlock()
		}
		select {
		case ready <- struct{}{}:
		default:
		}
		if events.Connected != nil {
			events.Connected()
		}
	})
	s.AddHandler(func(_ *discordgo.Session, _ *discordgo.Resumed) {
		if events.Connected != nil {
			events.Connected()
		}
	})
	s.AddHandler(func(_ *discordgo.Session, _ *discordgo.Disconnect) {
		if events.Disconnected != nil && !g.closed() {
			events.Disconnected()
		}
	})
	s.AddHandler(func(_ *discordgo.Session, ic *discordgo.InteractionCreate) {
		if i := convert(ic.Interaction); i != nil && events.Interaction != nil {
			events.Interaction(g, i)
		}
	})
	if err := s.Open(); err != nil {
		logToken(token, false)
		return nil, describe(err)
	}
	select {
	case <-ready:
		return g, nil
	case <-time.After(ReadyTimeout):
		err = errors.New("Discord did not say the bot is ready within 30 seconds")
	case <-ctx.Done():
		err = ctx.Err()
	}
	_ = g.Close()
	return nil, err
}

type gateway struct {
	s     *discordgo.Session
	self  User
	token string

	mu    sync.Mutex
	done  bool
	appID string
}

func (g *gateway) closed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.done
}

func (g *gateway) Self() User { return g.self }

func (g *gateway) ApplicationID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.appID != "" {
		return g.appID
	}
	return g.self.ID
}

func (g *gateway) Close() error {
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		return nil
	}
	g.done = true
	g.mu.Unlock()
	err := g.s.Close()
	logToken(g.token, false)
	return err
}

func (g *gateway) Register(guildID string, commands []CommandSpec) error {
	var list []*discordgo.ApplicationCommand
	for _, c := range commands {
		command := &discordgo.ApplicationCommand{Name: c.Name, Description: c.Description,
			Type: discordgo.ChatApplicationCommand}
		if c.AdminOnly {
			command.DefaultMemberPermissions = &adminPermissions
		}
		list = append(list, command)
	}
	_, err := g.s.ApplicationCommandBulkOverwrite(g.ApplicationID(), guildID, list)
	return describe(err)
}

// adminPermissions are those of a guild's admins: Manage Server (which
// Administrator implies).
var adminPermissions int64 = discordgo.PermissionManageGuild

// noMentions lets no mention in a message ping anyone.
var noMentions = &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}

func embeds(m Message) []*discordgo.MessageEmbed {
	out := []*discordgo.MessageEmbed{}
	for _, e := range m.Embeds {
		embed := &discordgo.MessageEmbed{Title: e.Title, URL: e.URL, Description: e.Description, Color: e.Color}
		if e.Footer != "" {
			embed.Footer = &discordgo.MessageEmbedFooter{Text: e.Footer}
		}
		if !e.Time.IsZero() {
			embed.Timestamp = e.Time.UTC().Format(time.RFC3339)
		}
		for _, f := range e.Fields {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{Name: f.Name, Value: f.Value,
				Inline: f.Inline})
		}
		out = append(out, embed)
	}
	return out
}

func components(m Message) []discordgo.MessageComponent {
	out := []discordgo.MessageComponent{}
	for _, sel := range m.Selects {
		menu := discordgo.SelectMenu{CustomID: sel.ID, Placeholder: sel.Placeholder, MinValues: &sel.Min,
			MaxValues: sel.Max}
		kind := discordgo.SelectMenuDefaultValueChannel
		switch sel.Kind {
		case ChannelSelect:
			menu.MenuType = discordgo.ChannelSelectMenu
			menu.ChannelTypes = []discordgo.ChannelType{discordgo.ChannelTypeGuildText}
		case RoleSelect:
			menu.MenuType, kind = discordgo.RoleSelectMenu, discordgo.SelectMenuDefaultValueRole
		}
		for _, id := range sel.Defaults {
			menu.DefaultValues = append(menu.DefaultValues, discordgo.SelectMenuDefaultValue{ID: id, Type: kind})
		}
		out = append(out, discordgo.ActionsRow{Components: []discordgo.MessageComponent{menu}})
	}
	if len(m.Buttons) == 0 {
		return out
	}
	row := discordgo.ActionsRow{}
	for _, b := range m.Buttons {
		style := map[Style]discordgo.ButtonStyle{Primary: discordgo.PrimaryButton, Secondary: discordgo.SecondaryButton,
			Success: discordgo.SuccessButton, Danger: discordgo.DangerButton, Link: discordgo.LinkButton}[b.Style]
		if b.Style == Link {
			row.Components = append(row.Components, discordgo.Button{Label: b.Label, Style: style, URL: b.URL})
			continue
		}
		row.Components = append(row.Components, discordgo.Button{Label: b.Label, Style: style, CustomID: b.ID})
	}
	return append(out, row)
}

func (g *gateway) Reply(i *Interaction, r Reply) error {
	raw, ok := i.Raw.(*discordgo.Interaction)
	if !ok {
		return errors.New("not a Discord interaction")
	}
	response := &discordgo.InteractionResponse{Type: discordgo.InteractionResponseChannelMessageWithSource}
	switch {
	case r.Modal != nil:
		response.Type = discordgo.InteractionResponseModal
		data := &discordgo.InteractionResponseData{CustomID: r.Modal.ID, Title: r.Modal.Title}
		for _, in := range r.Modal.Inputs {
			style := discordgo.TextInputShort
			if in.Long {
				style = discordgo.TextInputParagraph
			}
			data.Components = append(data.Components, discordgo.ActionsRow{Components: []discordgo.MessageComponent{
				discordgo.TextInput{CustomID: in.ID, Label: in.Label, Style: style, Placeholder: in.Placeholder,
					Value: in.Value, Required: in.Required, MinLength: in.Min, MaxLength: in.Max}}})
		}
		response.Data = data
	case r.Message != nil:
		if r.Update {
			response.Type = discordgo.InteractionResponseUpdateMessage
		}
		data := &discordgo.InteractionResponseData{Content: r.Message.Content, Embeds: embeds(*r.Message),
			Components: components(*r.Message), AllowedMentions: noMentions}
		if r.Ephemeral {
			data.Flags = discordgo.MessageFlagsEphemeral
		}
		response.Data = data
	}
	return describe(g.s.InteractionRespond(raw, response))
}

func (g *gateway) Send(channelID string, m Message) (string, error) {
	sent, err := g.s.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{Content: m.Content,
		Embeds: embeds(m), Components: components(m), AllowedMentions: noMentions})
	if err != nil {
		return "", describe(err)
	}
	return sent.ID, nil
}

func (g *gateway) Edit(channelID, messageID string, m Message) error {
	content, list, rows := m.Content, embeds(m), components(m)
	_, err := g.s.ChannelMessageEditComplex(&discordgo.MessageEdit{ID: messageID, Channel: channelID,
		Content: &content, Embeds: &list, Components: &rows, AllowedMentions: noMentions})
	return describe(err)
}

func (g *gateway) DM(userID string, m Message) error {
	channel, err := g.s.UserChannelCreate(userID)
	if err != nil {
		return describe(err)
	}
	_, err = g.Send(channel.ID, m)
	return err
}

// convert reads a library's interaction (nil for one the bot does not
// answer).
func convert(in *discordgo.Interaction) *Interaction {
	i := &Interaction{GuildID: in.GuildID, ChannelID: in.ChannelID, Raw: in}
	if in.Member != nil && in.Member.User != nil {
		i.User = User{ID: in.Member.User.ID, Name: in.Member.User.Username}
		i.Roles = in.Member.Roles
		// (the member's permissions in the channel, which come with each
		// interaction)
		i.Admin = in.Member.Permissions&(discordgo.PermissionAdministrator|discordgo.PermissionManageGuild) != 0
	} else if in.User != nil {
		i.User = User{ID: in.User.ID, Name: in.User.Username}
	}
	if in.Message != nil {
		i.MessageID = in.Message.ID
	}
	switch in.Type {
	case discordgo.InteractionApplicationCommand:
		i.Kind, i.Name = Command, in.ApplicationCommandData().Name
	case discordgo.InteractionMessageComponent:
		data := in.MessageComponentData()
		i.Kind, i.CustomID = Button, data.CustomID
		if data.ComponentType != discordgo.ButtonComponent {
			i.Kind, i.Selected = Select, data.Values
		}
	case discordgo.InteractionModalSubmit:
		data := in.ModalSubmitData()
		i.Kind, i.CustomID, i.Values = ModalSubmit, data.CustomID, map[string]string{}
		for _, c := range data.Components {
			row, ok := c.(*discordgo.ActionsRow)
			if !ok {
				continue
			}
			for _, inner := range row.Components {
				if input, ok := inner.(*discordgo.TextInput); ok {
					i.Values[input.CustomID] = input.Value
				}
			}
		}
	default:
		return nil
	}
	return i
}
