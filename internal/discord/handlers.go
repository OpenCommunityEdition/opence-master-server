package discord

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

// The custom ids' prefixes: the button that opens the application form,
// the form, and an application's Approve and Deny buttons and denial form;
// and /configure's select menus.
const (
	idForm          = "apply:form:"
	idSubmit        = "apply:submit:"
	idApprove       = "app:approve:"
	idDeny          = "app:deny:"
	idDenyReason    = "app:denyreason:"
	idConfigChannel = "config:channel"
	idConfigRoles   = "config:roles"
	idUpdate        = "update:start:"
)

// The application form's inputs (a modal holds 5 at most: the number of
// servers and the region share one).
const (
	inputName    = "name"
	inputKey     = "public_key"
	inputProof   = "proof"
	inputServers = "servers"
	inputNote    = "note"
	inputReason  = "reason"
)

// what each refused field is called on the form
var fieldLabels = map[string]string{"name": "Display name", "public_key": "Public key", "proof": "Proof of key",
	"servers": "Servers and region", "region": "Servers and region", "note": "Note", "discord": "your Discord username"}

// Embed colours.
const (
	colourPending  = 0x5865f2
	colourApproved = 0x57f287
	colourDenied   = 0xed4245
)

// draftLife is how long a refused form's inputs are kept for the next try.
const draftLife = time.Hour

// Actor is the audit log's name of a Discord member.
func Actor(u User) string { return "discord:" + u.ID + " " + u.Name }

func ephemeral(text string, buttons ...ButtonSpec) Reply {
	return Reply{Ephemeral: true, Message: &Message{Content: text, Buttons: buttons}}
}

// handle answers an interaction of the generation's connection.
func (b *Bot) handle(generation uint64, c Client, i *Interaction) {
	_, s, current := b.current(generation)
	if !current {
		return
	}
	reply := func(r Reply) {
		if err := c.Reply(i, r); err != nil {
			b.Log.Warn("discord: reply not sent", "err", err)
		}
	}
	if i.GuildID != s.Guild {
		reply(ephemeral("This bot takes applications in its own Discord server only."))
		return
	}
	switch {
	case i.Kind == Command && i.Name == "apply":
		reply(b.applyCommand(i))
	case i.Kind == Command && (i.Name == "configure" || i.Name == "config"):
		if !i.Admin {
			reply(ephemeral(adminRefusal))
			return
		}
		reply(Reply{Ephemeral: true, Message: ptr(configureMessage(s, ""))})
	case i.Kind == Select && (i.CustomID == idConfigChannel || i.CustomID == idConfigRoles):
		reply(b.choose(c, i))
	case i.Kind == Button && strings.HasPrefix(i.CustomID, idUpdate):
		reply(b.updateButton(i))
	case i.Kind == Button && strings.HasPrefix(i.CustomID, idForm):
		reply(Reply{Modal: b.applicationForm(i.User.ID, strings.TrimPrefix(i.CustomID, idForm))})
	case i.Kind == ModalSubmit && strings.HasPrefix(i.CustomID, idSubmit):
		reply(b.submit(i, strings.TrimPrefix(i.CustomID, idSubmit)))
	case i.Kind == Button && strings.HasPrefix(i.CustomID, idApprove):
		b.decide(c, s, i, strings.TrimPrefix(i.CustomID, idApprove), "")
	case i.Kind == Button && strings.HasPrefix(i.CustomID, idDeny):
		id := strings.TrimPrefix(i.CustomID, idDeny)
		if why := approverRefusal(s, i); why != "" {
			reply(ephemeral(why))
			return
		}
		a, err := b.M.Store.Application(id)
		if err != nil {
			reply(ephemeral("No application " + id + "."))
			return
		}
		if a.Status != model.ApplicationPending {
			b.ApplicationChanged(id)
			reply(ephemeral(fmt.Sprintf("Application %s is %s already.", id, a.Status)))
			return
		}
		reply(Reply{Modal: &Modal{ID: idDenyReason + id, Title: "Deny application " + id, Inputs: []Input{{
			ID: inputReason, Label: "Reason, told to the applicant", Long: true, Required: true, Min: 1, Max: 300}}}})
	case i.Kind == ModalSubmit && strings.HasPrefix(i.CustomID, idDenyReason):
		b.decide(c, s, i, strings.TrimPrefix(i.CustomID, idDenyReason), strings.TrimSpace(i.Values[inputReason]))
	default:
		reply(ephemeral("This button or command is not this bot's any more."))
	}
}

// approverRefusal says why a member may not decide applications (empty if
// they may).
func approverRefusal(s Settings, i *Interaction) string {
	if len(s.Roles) == 0 {
		return "No approver role is set: nobody may decide here until a server admin chooses one with /configure."
	}
	for _, have := range i.Roles {
		for _, want := range s.Roles {
			if have == want {
				return ""
			}
		}
	}
	return "Only members with an approver role may decide applications."
}

const adminRefusal = "Only the server's admins (Administrator or Manage Server) may configure this bot."

// configureMessage is /configure's: the settings, with select menus for
// those the environment does not set, and what the last choice did.
func configureMessage(s Settings, outcome string) Message {
	channel, roles := "none: the applications are not posted", "none: nobody may decide"
	if s.Channel != "" {
		channel = "<#" + s.Channel + ">"
	}
	if len(s.Roles) > 0 {
		var mentions []string
		for _, r := range s.Roles {
			mentions = append(mentions, "<@&"+r+">")
		}
		roles = strings.Join(mentions, ", ")
	}
	text := "**Applications log channel**: " + channel + "\n**Approver roles**: " + roles + "\n"
	m := Message{}
	if s.FromEnv["channel"] {
		text += "The channel is set by the master's environment (MASTER_DISCORD_CHANNEL).\n"
	} else {
		text += "The channel is where each application is posted with Approve and Deny buttons: keep it to the " +
			"approvers. The bot needs View Channel, Send Messages and Embed Links there.\n"
		m.Selects = append(m.Selects, SelectSpec{ID: idConfigChannel, Placeholder: "Applications log channel",
			Kind: ChannelSelect, Min: 1, Max: 1, Defaults: nonEmpty(s.Channel)})
	}
	if s.FromEnv["roles"] {
		text += "The roles are set by the master's environment (MASTER_DISCORD_APPROVER_ROLES).\n"
	} else {
		text += fmt.Sprintf("The members of an approver role (%d at most) may approve and deny.\n", MaximumRoles)
		m.Selects = append(m.Selects, SelectSpec{ID: idConfigRoles, Placeholder: "Approver roles", Kind: RoleSelect,
			Max: MaximumRoles, Defaults: s.Roles})
	}
	if outcome != "" {
		text += "\n" + outcome
	}
	m.Content = text
	return m
}

func nonEmpty(id string) []string {
	if id == "" {
		return nil
	}
	return []string{id}
}

// choose takes a choice on /configure's message: the log channel, once the
// bot has posted to it, or the approver roles.
func (b *Bot) choose(c Client, i *Interaction) Reply {
	if !i.Admin {
		return ephemeral(adminRefusal)
	}
	actor := Actor(i.User)
	var outcome string
	var err error
	if i.CustomID == idConfigChannel {
		if len(i.Selected) != 1 || checkChannel(i.Selected[0]) != nil {
			return ephemeral("Choose one channel.")
		}
		channel := i.Selected[0]
		_, err = c.Send(channel, Message{Content: fmt.Sprintf("The applications to %s are posted to this channel "+
			"(chosen by <@%s>).", escape(b.M.Name()), i.User.ID)})
		if err != nil {
			outcome = fmt.Sprintf("Not changed: the bot could not post to <#%s> (%v). Give it View Channel, Send "+
				"Messages and Embed Links there.", channel, err)
			err = nil
		} else if err = b.SetChannel(channel, actor); err == nil {
			outcome = "The applications are posted to <#" + channel + "> from now on."
		}
	} else {
		if err = checkRoles(i.Selected); err == nil {
			err = b.SetRoles(i.Selected, actor)
		}
		outcome = "The approver roles are saved."
	}
	if err != nil {
		outcome = "Not changed: " + err.Error() + "."
	}
	s, err := b.Settings()
	if err != nil {
		return ephemeral("The settings could not be read: " + err.Error())
	}
	return Reply{Update: true, Message: ptr(configureMessage(s, outcome))}
}

func (b *Bot) applyCommand(i *Interaction) Reply {
	nonce := b.M.ProofNonce(i.User.ID)
	proof := "Show that you hold the key: on the server, run"
	if !b.M.Config.RequireProof {
		proof = "Optionally (an application without it is flagged as unproven), show that you hold the key: run"
	}
	text := fmt.Sprintf("**Apply to publish OpenCE dedicated servers on %s**\n"+
		"1. On the server, make its publisher key once with `halo --server --keygen`: it writes `publisher.key` "+
		"beside `config.toml` and prints the public key (`ed25519:...`) and its key id. The private key never "+
		"leaves the server.\n"+
		"2. %s\n`halo --server --sign %s`\nand keep what it prints. This nonce is good for 24 hours, for your "+
		"applications only.\n"+
		"3. Press **Fill in the application**, and paste the public key and the signature.\n"+
		"Your server may publish meanwhile: the master tells it `publisher_pending` until an approver decides, "+
		"and lists it at its next publish after an approval. You are told of the decision by a direct message. "+
		"The masters share approvals, so one application is enough.", escape(b.M.Name()), proof, nonce)
	return ephemeral(text, ButtonSpec{ID: idForm + nonce, Label: "Fill in the application", Style: Primary})
}

// applicationForm is the application's modal, filled in with a refused
// try's inputs.
func (b *Bot) applicationForm(userID, nonce string) *Modal {
	values := map[string]string{inputServers: "1"}
	b.mu.Lock()
	if d, ok := b.drafts[userID]; ok && b.M.Now().Sub(d.at) < draftLife {
		values = d.values
	}
	b.mu.Unlock()
	proofLabel := "Proof of key: what --sign printed"
	if !b.M.Config.RequireProof {
		proofLabel += " (optional)"
	}
	form := &Modal{ID: idSubmit + nonce, Title: "Apply to publish servers", Inputs: []Input{
		{ID: inputName, Label: "Display name, shown beside your servers", Required: true, Min: 3, Max: 32,
			Value: values[inputName]},
		{ID: inputKey, Label: "Public key (halo --server --keygen)", Placeholder: "ed25519:...", Required: true,
			Max: 100, Value: values[inputKey]},
		{ID: inputProof, Label: proofLabel, Placeholder: "128 hexadecimal digits", Required: b.M.Config.RequireProof,
			Max: 200, Value: values[inputProof]},
		{ID: inputServers, Label: "Servers at once, and a region: 2 eu", Placeholder: "1", Required: true, Max: 24,
			Value: values[inputServers]},
		{ID: inputNote, Label: "Note to the approvers (optional)", Long: true, Max: 1000, Value: values[inputNote]},
	}}
	// (Discord refuses a form whose value is outside its input's lengths)
	for n := range form.Inputs {
		in := &form.Inputs[n]
		if len(in.Value) < in.Min || len(in.Value) > in.Max {
			in.Value = ""
		}
	}
	return form
}

// submit takes the application form.
func (b *Bot) submit(i *Interaction, nonce string) Reply {
	values := map[string]string{}
	for _, id := range []string{inputName, inputKey, inputProof, inputServers, inputNote} {
		values[id] = i.Values[id]
	}
	in := core.ApplicationInput{Name: values[inputName], PublicKey: values[inputKey], Note: values[inputNote],
		DiscordID: i.User.ID, DiscordName: username(i.User.Name)}
	if signature := strings.TrimSpace(values[inputProof]); signature != "" {
		in.Proof = &core.Proof{Nonce: nonce, Signature: signature}
	}
	retry := ButtonSpec{ID: idForm + nonce, Label: "Try again", Style: Primary}
	fields := strings.Fields(values[inputServers])
	servers, err := 0, error(nil)
	if len(fields) > 0 {
		servers, err = strconv.Atoi(fields[0])
	}
	if len(fields) == 0 || len(fields) > 2 || err != nil {
		b.keepDraft(i.User.ID, values)
		return ephemeral("Your application was not taken: **Servers and region** is a number of servers at "+
			"once, then a region if you like (`2 eu`).", retry)
	}
	in.Servers = servers
	if len(fields) == 2 {
		in.Region = fields[1]
	}
	a, err := b.M.Apply(in, Actor(i.User))
	if err != nil {
		var field *core.FieldError
		var action *core.ActionError
		var limited *core.LimitError
		switch {
		case errors.As(err, &limited):
			return ephemeral("Your application was not taken: " + limited.Message + ". Try again later.")
		case errors.As(err, &field):
			b.keepDraft(i.User.ID, values)
			text := fmt.Sprintf("Your application was not taken: **%s**: %s.", fieldLabels[field.Field], field.Message)
			if field.Field == "proof" {
				text += " If the nonce expired, run `/apply` again for a new one, and sign that."
			}
			return ephemeral(text, retry)
		case errors.As(err, &action) && action.Code == "duplicate" && strings.HasPrefix(action.Message, "your"):
			return ephemeral("Your application was not taken: " + action.Message + ".")
		case errors.As(err, &action):
			b.keepDraft(i.User.ID, values)
			return ephemeral("Your application was not taken: "+action.Message+".", retry)
		}
		b.Log.Error("discord: application failed", "err", err)
		return ephemeral("The master failed to take your application; try again later.")
	}
	b.mu.Lock()
	delete(b.drafts, i.User.ID)
	b.mu.Unlock()
	proof := ""
	if !a.ProofOK {
		proof = " It has no proof of key, so the approvers are told that anyone may have sent this key."
	}
	return ephemeral(fmt.Sprintf("Application `%s` received: key `%s`, %d %s at once.%s It waits for an "+
		"approver; you are told of the decision by a direct message (from this bot: allow direct messages from "+
		"this server's members to get it). Your server may publish meanwhile: it is told `publisher_pending` "+
		"until the approval, then it is listed at its next publish.", a.ID, a.KeyID, a.Servers,
		plural(a.Servers, "server", "servers"), proof))
}

func (b *Bot) keepDraft(userID string, values map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.M.Now()
	if len(b.drafts) >= 1000 {
		for id, d := range b.drafts {
			if now.Sub(d.at) >= draftLife {
				delete(b.drafts, id)
			}
		}
		if len(b.drafts) >= 1000 {
			b.drafts = map[string]draft{}
		}
	}
	b.drafts[userID] = draft{values: values, at: now}
}

// decide approves an application (no reason) or denies it, for an
// approver, and shows the outcome on its message at once.
func (b *Bot) decide(c Client, s Settings, i *Interaction, id, reason string) {
	reply := func(r Reply) {
		if err := c.Reply(i, r); err != nil {
			b.Log.Warn("discord: reply not sent", "err", err)
		}
	}
	if why := approverRefusal(s, i); why != "" {
		reply(ephemeral(why))
		return
	}
	actor := Actor(i.User)
	b.mu.Lock()
	b.deciding[id] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.deciding, id)
		b.mu.Unlock()
		b.ApplicationChanged(id)
	}()
	var err error
	if strings.HasPrefix(i.CustomID, idApprove) {
		_, err = b.M.Approve(id, 0, actor)
	} else if reason == "" {
		err = errors.New("a denial needs a reason")
	} else {
		err = b.M.Deny(id, reason, actor)
	}
	if err != nil {
		reply(ephemeral("Not done: " + err.Error() + "."))
		return
	}
	a, err := b.M.Store.Application(id)
	if err != nil {
		reply(ephemeral("Done, but the application could not be read again: " + err.Error()))
		return
	}
	if i.MessageID == "" || i.MessageID != a.LogMessage {
		reply(ephemeral(fmt.Sprintf("Application %s is %s.", a.ID, a.Status)))
		return
	}
	if err := b.M.Store.SetApplicationShown(a.ID, a.Status); err != nil {
		b.Log.Warn("discord: not recorded", "err", err)
	}
	if err := c.Reply(i, Reply{Update: true, Message: ptr(b.applicationMessage(a))}); err != nil {
		// (the next synchronisation edits the message)
		b.Log.Warn("discord: message not updated", "id", a.ID, "err", err)
		_ = b.M.Store.SetApplicationShown(a.ID, a.LogStatus)
	}
}

func ptr[T any](v T) *T { return &v }

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// username is a Discord username as an application keeps it: printable
// ASCII, 37 characters at most.
func username(name string) string {
	out := []byte{}
	for i := 0; i < len(name) && len(out) < 37; i++ {
		if name[i] >= 0x20 && name[i] < 0x7f {
			out = append(out, name[i])
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// escape keeps a text's Discord markdown from formatting it.
func escape(text string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`, ">", `\>`,
		"#", `\#`, "[", `\[`, "]", `\]`).Replace(text)
}

func cut(text string, n int) string {
	if len(text) > n {
		return text[:n-3] + "..."
	}
	return text
}

// who is a decision's actor as a message shows it.
func who(actor string) string {
	switch {
	case strings.HasPrefix(actor, "discord:"):
		id, _, _ := strings.Cut(strings.TrimPrefix(actor, "discord:"), " ")
		return "<@" + id + ">"
	case actor == "admin":
		return "an admin, on the website"
	case actor == "cli":
		return "the command line"
	case actor == "":
		return "someone"
	}
	return escape(actor)
}

func (b *Bot) adminLink(id string) string {
	if b.M.Config.PublicURL == "" {
		return ""
	}
	return b.M.Config.PublicURL + "/admin/applications/" + id
}

// applicationMessage is an application's log channel message: its details,
// the other applications from the same Discord user or for the same key,
// and its outcome, with the Approve and Deny buttons while it is pending.
func (b *Bot) applicationMessage(a *model.Application) Message {
	e := Embed{Title: "Application " + a.ID, URL: b.adminLink(a.ID), Color: colourPending, Footer: b.M.Name(),
		Time: time.Unix(a.Created, 0)}
	applicant := "added on the command line"
	switch {
	case a.DiscordID != "":
		applicant = fmt.Sprintf("<@%s> (%s)", a.DiscordID, escape(a.Discord))
	case a.Email != "":
		applicant = "the web form, " + escape(a.Email)
	}
	region := a.Region
	if region == "" {
		region = "-"
	}
	proof := "verified"
	if !a.ProofOK {
		proof = "**NONE**: anyone may have sent this key; confirm it with the operator before approving"
	}
	e.Fields = []Field{
		{Name: "Name", Value: escape(a.Name), Inline: true},
		{Name: "Applicant", Value: applicant, Inline: true},
		{Name: "Servers", Value: fmt.Sprintf("%d, region %s", a.Servers, escape(region)), Inline: true},
		{Name: "Key id", Value: "`" + a.KeyID + "`", Inline: true},
		{Name: "Proof of key", Value: proof, Inline: true},
	}
	if a.Note != "" {
		e.Fields = append(e.Fields, Field{Name: "Note", Value: cut(escape(a.Note), 1000)})
	}
	related, err := b.M.Store.RelatedApplications(a)
	others := "none"
	if err != nil {
		others = "(not read)"
	} else if len(related) > 0 {
		var lines []string
		for n, r := range related {
			if n == 5 {
				lines = append(lines, fmt.Sprintf("and %d more", len(related)-5))
				break
			}
			same := "same key"
			if r.KeyID != a.KeyID {
				same = "same Discord user"
			}
			lines = append(lines, fmt.Sprintf("`%s` %s (%s), <t:%d:d>", r.ID, r.Status, same, r.Created))
		}
		others = strings.Join(lines, "\n")
	}
	e.Fields = append(e.Fields, Field{Name: "Other applications", Value: others})
	if e.URL == "" {
		e.Fields = append(e.Fields, Field{Name: "Admin page", Value: "/admin/applications/" + a.ID})
	}
	m := Message{}
	switch a.Status {
	case model.ApplicationApproved:
		e.Color = colourApproved
		e.Fields = append(e.Fields, Field{Name: "Approved", Value: fmt.Sprintf("by %s, <t:%d:f>: publisher `%s`",
			who(a.DecidedBy), a.Updated, a.PublisherID)})
	case model.ApplicationDenied:
		e.Color = colourDenied
		e.Fields = append(e.Fields, Field{Name: "Denied", Value: fmt.Sprintf("by %s, <t:%d:f>: %s",
			who(a.DecidedBy), a.Updated, cut(escape(a.Reason), 700))})
	default:
		e.Fields = append(e.Fields, Field{Name: "Status", Value: "waiting for an approver"})
		m.Buttons = []ButtonSpec{{ID: idApprove + a.ID, Label: "Approve", Style: Success},
			{ID: idDeny + a.ID, Label: "Deny", Style: Danger}}
	}
	m.Embeds = []Embed{e}
	return m
}

// decisionMessage tells a Discord applicant of their application's
// decision.
func (b *Bot) decisionMessage(a *model.Application) Message {
	name := escape(b.M.Name())
	if a.Status == model.ApplicationApproved {
		quota := b.M.Config.DefaultQuota
		if state, err := b.M.State(a.PublisherID); err == nil {
			quota = state.Quota
		}
		return Message{Content: fmt.Sprintf("Your application `%s` to %s is approved: you are publisher `%s`, "+
			"with up to %d %s at once. A server publishing with key `%s` is listed at its next publish (within 30 "+
			"seconds), once its UDP port answers the master's probe. The masters share approvals: the other "+
			"official masters list it too.", a.ID, name, a.PublisherID, quota, plural(quota, "server", "servers"),
			a.KeyID)}
	}
	text := fmt.Sprintf("Your application `%s` to %s was not approved: %s", a.ID, name, escape(a.Reason))
	if contact := b.M.Contact(); contact != "" {
		text += "\nContact: " + escape(contact)
	}
	return Message{Content: text}
}

var _ core.Watcher = (*Bot)(nil)
