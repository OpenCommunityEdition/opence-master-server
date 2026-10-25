// Package view is what the public and the admin pages share: the page's
// common fields, the document around a page, the components (cards,
// buttons, inputs, badges, tables) and their classes, and rendering. The
// pages are templ components (*.templ, from which `go tool templ generate`
// writes *_templ.go), styled with Tailwind (style.css, from which
// tools/generate.sh writes the stylesheet the master serves). They work
// without JavaScript.
package view

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
)

// Page is what every page's layout reads.
type Page struct {
	Title    string
	Master   string
	Contact  string
	Policy   string
	KeyID    string
	Version  string
	Protocol int
	// the admin pages': whether the admin is logged in, the session's CSRF
	// token, the section of the navigation the page is in, a newer release
	// out, and an action's outcome, shown once
	Signed       bool
	CSRF         string
	Section      string
	UpdateBanner string
	Notice       string
	Error        string
}

// For fills a page's common fields from the master.
func For(m *core.Master, title string) Page {
	return Page{Title: title, Master: m.Name(), Contact: m.Contact(), Policy: m.Config.DataPolicy,
		KeyID: m.KeyID, Version: core.Version, Protocol: core.Protocol}
}

// Render writes a page: rendered whole first, so a failure answers an error
// rather than half a page.
func Render(w http.ResponseWriter, r *http.Request, status int, page templ.Component) {
	var buffer bytes.Buffer
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	if err := page.Render(ctx, &buffer); err != nil {
		http.Error(w, "the page failed", http.StatusInternalServerError)
		return
	}
	httpx.Secure(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}

// Time writes a Unix time for the pages ("never" for none).
func Time(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return TimeText(unix)
}

// TimeText writes a Unix time, in UTC.
func TimeText(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

// Since writes how long ago a Unix time was.
func Since(unix int64) string { return core.Since(unix) }

// Plural is one or many, by n.
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// The components' classes (Tailwind's: tools/generate.sh finds them here).
const (
	buttonBase = "inline-flex cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-md " +
		"px-4 py-2 text-sm font-medium transition focus-visible:outline-2 focus-visible:outline-offset-2 " +
		"focus-visible:outline-accent disabled:pointer-events-none disabled:opacity-50"
	// ButtonPrimary is the main action: the text's colour, filled.
	ButtonPrimary = buttonBase + " bg-fg text-canvas hover:bg-fg/85"
	// ButtonSecondary is an outlined button.
	ButtonSecondary = buttonBase + " border border-line bg-transparent text-fg hover:bg-fg/5"
	// ButtonDanger is an action that refuses, suspends or revokes.
	ButtonDanger = buttonBase + " bg-red-600 text-white hover:bg-red-700"
	// ButtonSmall shrinks a button (with one of the above).
	ButtonSmall = " px-3 py-1.5 text-xs"

	// Input is a text, number or password input.
	Input = "w-full rounded-md border border-line bg-transparent px-3 py-2 text-sm placeholder:text-muted " +
		"transition focus-visible:border-accent focus-visible:outline-2 focus-visible:outline-accent/30 " +
		"disabled:cursor-not-allowed disabled:opacity-60"
	// InputInline is an input beside others, in a row.
	InputInline = "rounded-md border border-line bg-transparent px-3 py-1.5 text-sm placeholder:text-muted " +
		"focus-visible:border-accent focus-visible:outline-2 focus-visible:outline-accent/30"
	// Checkbox is a checkbox.
	Checkbox = "size-4 rounded border-line accent-fg"
	// Link is a link styled as one (a link in running text needs none).
	Link = "text-accent underline-offset-2 hover:underline"
)

// Tone is a badge's or an alert's colour.
type Tone int

// The tones.
const (
	Neutral Tone = iota
	OK
	Warn
	Bad
	Info
)

// ToneClass is a tone's badge classes.
func ToneClass(t Tone) string {
	base := "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap "
	switch t {
	case OK:
		return base + "border-ok/30 bg-ok/10 text-ok"
	case Warn:
		return base + "border-warn/30 bg-warn/10 text-warn"
	case Bad:
		return base + "border-bad/30 bg-bad/10 text-bad"
	case Info:
		return base + "border-accent/30 bg-accent/10 text-accent"
	}
	return base + "border-line bg-fg/5 text-muted"
}

// StatusTone is the tone of a status: an application's, a publisher's, a
// key's or the bot's.
func StatusTone(status string) Tone {
	switch status {
	case "approved", "active", "connected", "listed", "verified":
		return OK
	case "pending", "connecting":
		return Warn
	case "denied", "suspended", "revoked", "error":
		return Bad
	}
	return Neutral
}

// alertRole is an alert's role: an error interrupts, a notice does not.
func alertRole(t Tone) string {
	if t == Bad {
		return "alert"
	}
	return "status"
}
