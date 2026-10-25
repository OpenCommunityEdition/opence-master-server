// Package web is the master's public pages: the server list, and how to
// apply (with the master's Discord bot).
package web

import (
	_ "embed"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
	"github.com/OpenCommunityEdition/opence-master-server/internal/view"
)

// Style is the pages' stylesheet (tools/generate.sh writes it from
// internal/view/style.css).
//
//go:embed static/style.css
var Style []byte

// Message is a page of a heading and lines.
type Message struct {
	Heading string
	Lines   []string
}

// Pages serves the public pages.
type Pages struct {
	M       *core.Master
	Clients *httpx.Clients
	// the list page's requests, MASTER_LIST_RATE a minute per address (the
	// API's list limiter, shared, when the command sets it)
	Lists *limit.Limiter
	// the Discord bot, which takes the applications (nil: none)
	Applying Applying
}

// Applying is what the /apply page shows of the Discord bot.
type Applying interface {
	// the invite to the bot's Discord server (empty: none set)
	InviteURL() string
	// whether the bot is connected
	Accepting() bool
}

// New makes the pages.
func New(m *core.Master, clients *httpx.Clients) (*Pages, error) {
	return &Pages{M: m, Clients: clients,
		Lists: limit.PerMinute(m.Config.ListPerMinute, func() time.Time { return m.Now() }).Grouped(netaddr.Group)}, nil
}

// Routes adds the pages to a mux.
func (p *Pages) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", p.index)
	mux.HandleFunc("GET /apply", p.apply)
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(Style)
	})
}

func (p *Pages) message(w http.ResponseWriter, r *http.Request, status int, title string, m Message) {
	view.Render(w, r, status, messagePage(view.For(p.M, title), m))
}

func (p *Pages) index(w http.ResponseWriter, r *http.Request) {
	if allowed, wait := p.Lists.Allow(p.Clients.Of(r).Key()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		p.message(w, r, http.StatusTooManyRequests, "Too many requests", Message{Heading: "Too many requests",
			Lines: []string{"Wait a few seconds and reload the page."}})
		return
	}
	entries, err := p.M.Listed(core.Filter{})
	if err != nil {
		p.message(w, r, http.StatusInternalServerError, "Error", Message{Heading: "The list failed"})
		return
	}
	players := 0
	for _, e := range entries {
		players += e.Players
	}
	page := view.For(p.M, "Servers")
	page.Section = "servers"
	view.Render(w, r, http.StatusOK, indexPage(page, entries, players))
}

func (p *Pages) apply(w http.ResponseWriter, r *http.Request) {
	invite, accepting := "", false
	if p.Applying != nil {
		invite, accepting = p.Applying.InviteURL(), p.Applying.Accepting()
	}
	page := view.For(p.M, "Apply")
	page.Section = "apply"
	view.Render(w, r, http.StatusOK, applyPage(page, invite, p.M.Config.RequireProof, accepting))
}

// SameOrigin tells whether a form post's Origin (when sent) is this page's:
// the request's host, or the one a trusted proxy forwards
// (X-Forwarded-Host). An Origin of "null" (a browser's, for a page whose
// referrer policy hides it, or a sandboxed frame's) is taken only when the
// browser itself says the request is same-origin (Sec-Fetch-Site, which a
// page cannot set).
func SameOrigin(r *http.Request, clients *httpx.Clients) bool {
	origin := r.Header.Get("Origin")
	if origin == "null" {
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, clients.Host(r))
}

// optional is the apply page's note that a proof of key may be left out.
func optional(yes bool) string {
	if yes {
		return " (optional on this master)"
	}
	return ""
}
