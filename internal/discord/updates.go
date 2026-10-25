package discord

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/update"
)

// Updates is what the bot needs of the master's updater.
type Updates interface {
	Status() update.Status
	// installs the latest release and restarts into it, on its own
	// goroutine
	Start(actor string) error
}

// keyUpdateNotice is the update notice in the log channel, in the database
// (JSON), so a restarted master edits the message the old one posted.
const keyUpdateNotice = "discord.update_notice"

// The notice's states: a newer release is out, it is being installed, it
// failed, or the master runs it (or a newer one).
const (
	noticeAvailable = "available"
	noticeUpdating  = "updating"
	noticeFailed    = "failed"
	noticeDone      = "done"
)

// notice is the update notice: the release, its message, what the message
// should show (Shown) and what it shows (Posted).
type notice struct {
	Version, URL, Notes string
	Channel, Message    string
	Shown, Posted       string
	// who started the update; the failure
	Actor, Error string
	// the notice of an older release, to be marked superseded
	OldChannel, OldMessage string
}

func (b *Bot) loadNotice() (*notice, error) {
	text, set, err := b.M.Store.Setting(keyUpdateNotice)
	if err != nil || !set {
		return nil, err
	}
	n := &notice{}
	if err := json.Unmarshal([]byte(text), n); err != nil {
		// (unreadable: dropped)
		return nil, nil
	}
	return n, nil
}

func (b *Bot) saveNotice(n *notice) error {
	if n == nil {
		return b.M.Store.SetSetting(keyUpdateNotice, "")
	}
	data, _ := json.Marshal(n)
	return b.M.Store.SetSetting(keyUpdateNotice, string(data))
}

// changeNotice changes the stored notice (under the synchronisation's lock,
// which Sync holds while it posts).
func (b *Bot) changeNotice(change func(n *notice) *notice) {
	b.syncing.Lock()
	n, err := b.loadNotice()
	if err == nil {
		err = b.saveNotice(change(n))
	}
	b.syncing.Unlock()
	if err != nil {
		b.Log.Warn("discord: the update notice not stored", "err", err)
	}
	b.ApplicationChanged("")
}

// UpdateAvailable is the updater's: a newer release is out; the log channel
// is told (once a version).
func (b *Bot) UpdateAvailable(r update.Release) {
	b.changeNotice(func(n *notice) *notice {
		if n != nil && n.Version == r.Version {
			return n
		}
		next := &notice{Version: r.Version, URL: r.URL, Notes: cut(r.Notes, 1500), Shown: noticeAvailable}
		if n != nil {
			next.OldChannel, next.OldMessage = n.Channel, n.Message
		}
		return next
	})
}

// UpdateStarted is the updater's: the update to version started.
func (b *Bot) UpdateStarted(version, actor string) {
	b.changeNotice(func(n *notice) *notice {
		if n == nil || n.Version != version {
			n = &notice{Version: version}
		}
		n.Shown, n.Actor, n.Error = noticeUpdating, actor, ""
		return n
	})
}

// UpdateFailed is the updater's: the update to version failed.
func (b *Bot) UpdateFailed(version string, err error) {
	b.changeNotice(func(n *notice) *notice {
		if n == nil || n.Version != version {
			n = &notice{Version: version}
		}
		n.Shown, n.Error = noticeFailed, err.Error()
		return n
	})
}

// updateButton starts the update, for a server admin.
func (b *Bot) updateButton(i *Interaction) Reply {
	if !i.Admin {
		return ephemeral("Only the server's admins (Administrator or Manage Server) may update the master.")
	}
	if b.Updates == nil {
		return ephemeral("This master has no updater.")
	}
	if err := b.Updates.Start(Actor(i.User)); err != nil {
		return ephemeral("Not started: " + err.Error() + ".")
	}
	n, err := b.loadNotice()
	if err != nil || n == nil || i.MessageID == "" || n.Message != i.MessageID {
		return ephemeral("The update started; the master restarts on its own.")
	}
	b.syncing.Lock()
	n.Posted = noticeUpdating
	_ = b.saveNotice(n)
	b.syncing.Unlock()
	return Reply{Update: true, Message: ptr(b.noticeMessage(n))}
}

// syncUpdate brings the log channel's update notice in line (called by
// Sync, which holds the lock).
func (b *Bot) syncUpdate(client Client, s Settings) string {
	n, err := b.loadNotice()
	if err != nil || n == nil {
		return ""
	}
	running := core.Version
	if b.Updates != nil {
		running = b.Updates.Status().Current
	}
	switch {
	case !update.Newer(n.Version, running):
		n.Shown = noticeDone
	case n.Shown == noticeUpdating && b.Updates != nil && !b.Updates.Status().Updating:
		// (restarted, but not into the release: it failed to start)
		n.Shown = noticeFailed
		n.Error = "the master runs " + running + " still; its log tells why"
	}
	if n.OldMessage != "" {
		superseded := Message{Embeds: []Embed{{Title: "Superseded", Color: 0x99aab5,
			Description: "A newer release is out: see the notice below."}}}
		if err := client.Edit(n.OldChannel, n.OldMessage, superseded); err != nil && !Permanent(err) {
			return "the old update notice not edited: " + err.Error()
		}
		n.OldChannel, n.OldMessage = "", ""
	}
	switch {
	case n.Message == "" && n.Shown == noticeDone:
		// (never posted: nothing to say)
		return b.storeNotice(nil)
	case n.Message == "" && s.Channel != "":
		id, err := client.Send(s.Channel, b.noticeMessage(n))
		if err != nil {
			return fmt.Sprintf("the update notice not posted to channel %s: %v", s.Channel, err)
		}
		n.Channel, n.Message, n.Posted = s.Channel, id, n.Shown
	case n.Message != "" && n.Posted != n.Shown:
		if err := client.Edit(n.Channel, n.Message, b.noticeMessage(n)); err != nil && !Permanent(err) {
			return "the update notice not edited: " + err.Error()
		}
		n.Posted = n.Shown
	}
	if n.Shown == noticeDone && n.Posted == noticeDone {
		return b.storeNotice(nil)
	}
	return b.storeNotice(n)
}

func (b *Bot) storeNotice(n *notice) string {
	if err := b.saveNotice(n); err != nil {
		return err.Error()
	}
	return ""
}

func whoUpdated(actor string) string {
	if actor == "auto" {
		return "automatically (MASTER_UPDATES=auto)"
	}
	return "by " + who(actor)
}

// noticeMessage is the update notice's message for its state.
func (b *Bot) noticeMessage(n *notice) Message {
	running := core.Version
	if b.Updates != nil {
		running = b.Updates.Status().Current
	}
	e := Embed{URL: n.URL, Footer: b.M.Name(), Time: b.M.Now()}
	m := Message{}
	notes := ""
	if n.Notes != "" {
		notes = "\n\n" + n.Notes
	}
	switch n.Shown {
	case noticeUpdating:
		e.Title, e.Color = "Updating to "+n.Version, colourPending
		e.Description = fmt.Sprintf("Started %s. The master installs the release and restarts on its own, "+
			"without dropping its connections; this message says when it runs it.", whoUpdated(n.Actor))
	case noticeFailed:
		e.Title, e.Color = "The update to "+n.Version+" failed", colourDenied
		e.Description = fmt.Sprintf("%s\nThe master still runs %s.", cut(escape(n.Error), 1000), running)
		m.Buttons = []ButtonSpec{{ID: idUpdate + n.Version, Label: "Try again", Style: Primary}}
	case noticeDone:
		e.Title, e.Color = "Updated to "+n.Version, colourApproved
		e.Description = fmt.Sprintf("The master runs %s since <t:%d:f>.", running, b.M.Now().Unix())
		if n.Actor != "" {
			e.Description += " Updated " + whoUpdated(n.Actor) + "."
		}
	default:
		e.Title, e.Color = "Update available: "+n.Version, colourPending
		e.Description = fmt.Sprintf("This master runs %s. A server admin may update it: the master downloads the "+
			"release, checks its signature, and restarts into it without dropping its connections.%s",
			running, notes)
		m.Buttons = []ButtonSpec{{ID: idUpdate + n.Version, Label: "Update now", Style: Success}}
	}
	if n.URL != "" && strings.HasPrefix(n.URL, "https://") {
		m.Buttons = append(m.Buttons, ButtonSpec{Label: "Release notes", Style: Link, URL: n.URL})
	}
	if len(e.Description) > 4000 {
		e.Description = e.Description[:3997] + "..."
	}
	m.Embeds = []Embed{e}
	return m
}
