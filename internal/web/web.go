// Package web is the master's public pages: the server list, and how to
// apply (with the master's Discord bot).
package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/style.css
var Style []byte

// Page is what every page's layout reads.
type Page struct {
	Title    string
	Master   string
	Contact  string
	Policy   string
	KeyID    string
	Version  string
	Protocol int
	Admin    bool
	Data     any
}

// Message is a page of a heading and lines.
type Message struct {
	Heading string
	Lines   []string
}

// Pages serves the public pages.
type Pages struct {
	M       *core.Master
	Clients *httpx.Clients
	pages   map[string]*template.Template
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

// Parse makes a page's template set from the layout and the page.
func Parse(files embed.FS, layout string, names ...string) (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, name := range names {
		t, err := template.New(name).Funcs(Funcs).ParseFS(files, layout, "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

// New makes the pages.
func New(m *core.Master, clients *httpx.Clients) (*Pages, error) {
	pages, err := Parse(templateFiles, "templates/layout.html", "index", "apply", "message")
	if err != nil {
		return nil, err
	}
	return &Pages{M: m, Clients: clients, pages: pages,
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

// PageFor fills a page's common fields.
func PageFor(m *core.Master, title string, data any) Page {
	return Page{Title: title, Master: m.Name(), Contact: m.Contact(), Policy: m.Config.DataPolicy,
		KeyID: m.KeyID, Version: core.Version, Protocol: core.Protocol, Admin: true, Data: data}
}

// Render writes a page.
func Render(w http.ResponseWriter, t *template.Template, status int, page Page) {
	var buffer bytes.Buffer
	if err := t.ExecuteTemplate(&buffer, "layout", page); err != nil {
		http.Error(w, "the page failed", http.StatusInternalServerError)
		return
	}
	httpx.Secure(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}

// Funcs are the templates' helpers.
var Funcs = template.FuncMap{
	"since": core.Since,
	"time": func(unix int64) string {
		if unix == 0 {
			return "never"
		}
		return timeText(unix)
	},
	"short": func(text string, n int) string {
		if len(text) > n {
			return text[:n] + "..."
		}
		return text
	},
}

func (p *Pages) message(w http.ResponseWriter, status int, title string, m Message) {
	Render(w, p.pages["message"], status, PageFor(p.M, title, m))
}

func (p *Pages) index(w http.ResponseWriter, r *http.Request) {
	if allowed, wait := p.Lists.Allow(p.Clients.Of(r).Key()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		p.message(w, http.StatusTooManyRequests, "Too many requests", Message{Heading: "Too many requests",
			Lines: []string{"Wait a few seconds and reload the page."}})
		return
	}
	entries, err := p.M.Listed(core.Filter{})
	if err != nil {
		p.message(w, http.StatusInternalServerError, "Error", Message{Heading: "The list failed"})
		return
	}
	players := 0
	for _, e := range entries {
		players += e.Players
	}
	Render(w, p.pages["index"], http.StatusOK, PageFor(p.M, "Servers", map[string]any{
		"Servers": entries, "Players": players}))
}

func (p *Pages) apply(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"RequireProof": p.M.Config.RequireProof}
	if p.Applying != nil {
		data["Invite"], data["Accepting"] = p.Applying.InviteURL(), p.Applying.Accepting()
	}
	Render(w, p.pages["apply"], http.StatusOK, PageFor(p.M, "Apply", data))
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
