// Package discord is the master's Discord bot, which takes the operators'
// applications: its /apply command gives an applicant a proof-of-key nonce
// and a form, each new application is posted to a log channel with Approve
// and Deny buttons for the members of an approver role (the channel and the
// roles are chosen by the server's admins with /configure), and the message
// shows the outcome once the application is decided (on Discord, on the
// admin pages or on the command line). The applicant is told of the
// decision by a direct message.
//
// What the bot needs of Discord is the Client interface; gateway.go is the
// only file that talks to Discord (through discordgo), so the handlers are
// tested with a fake.
package discord

import (
	"context"
	"errors"
	"time"
)

// User is a Discord user: an id and a username.
type User struct {
	ID, Name string
}

// Kind is an interaction's kind.
type Kind int

// The interactions the bot answers.
const (
	// a slash command
	Command Kind = iota + 1
	// a button pressed
	Button
	// a modal (form) sent
	ModalSubmit
	// a select menu's choice
	Select
)

// Interaction is something a member did: a command, a button, a form.
type Interaction struct {
	Kind      Kind
	GuildID   string
	ChannelID string
	// the member (or user, in a direct message)
	User User
	// the member's roles in the guild (none in a direct message)
	Roles []string
	// the member may manage the guild (Administrator or Manage Server)
	Admin bool
	// the command's name
	Name string
	// the button's, the select menu's or the modal's custom id
	CustomID string
	// a modal's inputs, by their custom ids
	Values map[string]string
	// a select menu's chosen ids
	Selected []string
	// a command's options, by name (a whole number's in decimal)
	Options map[string]string
	// the message the button is on (or the modal was opened from)
	MessageID string
	// the library's interaction, for the reply
	Raw any
}

// Style is a button's style.
type Style int

// Button styles.
const (
	Primary Style = iota + 1
	Secondary
	Success
	Danger
	// a link (URL), which sends the bot nothing
	Link
)

// ButtonSpec is a button on a message.
type ButtonSpec struct {
	ID, Label string
	Style     Style
	// a link button's
	URL string
}

// Field is an embed's field.
type Field struct {
	Name, Value string
	Inline      bool
}

// Embed is a message's embed.
type Embed struct {
	Title, URL, Description string
	Color                   int
	Fields                  []Field
	Footer                  string
	Time                    time.Time
}

// SelectKind is what a select menu chooses among.
type SelectKind int

// Select menus' kinds.
const (
	// the guild's text channels
	ChannelSelect SelectKind = iota + 1
	// the guild's roles
	RoleSelect
)

// SelectSpec is a select menu on a message, filled in by Discord with the
// guild's channels or roles.
type SelectSpec struct {
	ID, Placeholder string
	Kind            SelectKind
	Min, Max        int
	// the ids chosen at first
	Defaults []string
}

// Message is a message the bot sends: no mention in it pings anyone.
type Message struct {
	Content string
	Embeds  []Embed
	// select menus, a row each
	Selects []SelectSpec
	// one row of buttons, after the select menus; no buttons nor select
	// menus removes a message's on an edit
	Buttons []ButtonSpec
}

// Input is a modal's text input.
type Input struct {
	ID, Label, Placeholder, Value string
	// a paragraph, not a line
	Long     bool
	Required bool
	Min, Max int
}

// Modal is a form (5 inputs at most).
type Modal struct {
	ID, Title string
	Inputs    []Input
}

// Reply answers an interaction: a message (Ephemeral: seen by the member
// only), the interaction's message replaced (Update: a button's, or the
// message a modal was opened from), or a modal.
type Reply struct {
	Message   *Message
	Ephemeral bool
	Update    bool
	Modal     *Modal
}

// CommandSpec is a slash command the bot registers.
type CommandSpec struct {
	Name, Description string
	// shown to the members who may manage the guild only (the bot checks
	// it again: a guild may change who sees a command)
	AdminOnly bool
	Options   []OptionSpec
}

// OptionSpec is a slash command's option: a string, from a list of choices
// when it has them (Discord shows them as a menu), or a whole number
// between Min and Max.
type OptionSpec struct {
	Name, Description string
	Integer           bool
	Required          bool
	Choices           []Choice
	Min, Max          int
}

// Choice is one of a string option's choices: its words, and its value.
type Choice struct {
	Name, Value string
}

// Client is the bot's connection to Discord.
type Client interface {
	// the bot's user
	Self() User
	// the bot's application id (the bot user's for most bots, not all)
	ApplicationID() string
	// replaces the guild's commands
	Register(guildID string, commands []CommandSpec) error
	Reply(i *Interaction, r Reply) error
	// posts a message to a channel, returning its id
	Send(channelID string, m Message) (string, error)
	Edit(channelID, messageID string, m Message) error
	// a direct message
	DM(userID string, m Message) error
	Close() error
}

// Events is what a connection tells the bot.
type Events struct {
	Interaction func(c Client, i *Interaction)
	// the connection was lost (Discord's library reconnects)
	Disconnected func()
	// connected again
	Connected func()
}

// Dialer connects a bot with a token; it returns once the bot is ready.
type Dialer func(ctx context.Context, token string, events Events) (Client, error)

// Error is Discord's refusal of a request.
type Error struct {
	// the HTTP status, or a gateway close code (4000 and up)
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Permanent tells whether an error will not pass by trying again: Discord
// refused the request (a 4xx other than 429, or a gateway close code for a
// bad token or intents).
func Permanent(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return (e.Status >= 400 && e.Status < 500 && e.Status != 429) || e.Status == 4004 ||
		(e.Status >= 4010 && e.Status <= 4014)
}
