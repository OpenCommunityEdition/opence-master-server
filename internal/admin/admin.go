// Package admin is the master's admin pages: applications, publishers and
// their keys, servers (hidden and trusted), peers, the Discord bot's
// settings, the master's name and contact, and the audit log. An admin logs
// in with the admin token (a session cookie follows), or a script sends it
// as "Authorization: Bearer <token>". The token is MASTER_ADMIN_TOKEN, else
// the one the first launch's setup made (setup.go). Every action goes to the
// audit log through package core.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/update"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

//go:embed templates/*.html
var templateFiles embed.FS

const (
	cookieName     = "opence_admin"
	sessionLife    = 12 * time.Hour
	sessionIdle    = 30 * time.Minute
	maximumSession = 16
)

type session struct {
	csrf    string
	created time.Time
	used    time.Time
	// a notice or an error shown once, by the next page (an action's
	// outcome, after its redirect)
	notice, problem string
}

// Admin serves the admin pages.
type Admin struct {
	M       *core.Master
	Clients *httpx.Clients
	// the Discord bot, whose settings the Discord page sets (nil: none)
	Discord *discord.Bot
	// the updater, which the settings page shows (nil: none)
	Updates *update.Updater
	pages   map[string]*template.Template

	mu       sync.Mutex
	sessions map[string]*session
	failures *limit.Limiter
	// the setup link's code, while there is no admin token
	setupCode string
}

// New makes the admin pages.
func New(m *core.Master, clients *httpx.Clients) (*Admin, error) {
	pages := map[string]*template.Template{}
	for name, files := range map[string][]string{
		"login": {"login"}, "applications": {"applications"}, "application": {"application"},
		"publishers": {"publishers"}, "publisher": {"publisher", "servertable"},
		"servers": {"servers", "servertable"}, "peers": {"peers"}, "audit": {"audit"}, "discord": {"discord"},
		"setup": {"setup", "profile"}, "settings": {"settings", "profile"},
	} {
		patterns := []string{"templates/layout.html"}
		for _, f := range files {
			patterns = append(patterns, "templates/"+f+".html")
		}
		t, err := template.New(name).Funcs(web.Funcs).ParseFS(templateFiles, patterns...)
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	a := &Admin{M: m, Clients: clients, pages: pages, sessions: map[string]*session{},
		failures: limit.New(5, 2*time.Minute, func() time.Time { return m.Now() }).Grouped(netaddr.Group)}
	has, err := a.hasToken()
	if err != nil {
		return nil, err
	}
	if !has {
		a.setupCode = randomHex(16)
	}
	return a, nil
}

// Routes adds the admin pages to a mux.
func (a *Admin) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/setup", a.setupPage)
	mux.HandleFunc("POST /admin/setup", a.setup)
	mux.HandleFunc("GET /admin/settings", a.guard(a.settingsPage))
	mux.HandleFunc("POST /admin/settings", a.guard(a.settingsSave))
	mux.HandleFunc("POST /admin/update/check", a.guard(a.updateCheck))
	mux.HandleFunc("POST /admin/update/start", a.guard(a.updateStart))
	mux.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /admin/login", a.loginForm)
	mux.HandleFunc("POST /admin/login", a.login)
	mux.HandleFunc("POST /admin/logout", a.guard(a.logout))
	mux.HandleFunc("GET /admin/applications", a.guard(a.applications))
	mux.HandleFunc("GET /admin/applications/{id}", a.guard(a.application))
	mux.HandleFunc("POST /admin/applications/{id}/approve", a.guard(a.approve))
	mux.HandleFunc("POST /admin/applications/{id}/deny", a.guard(a.deny))
	mux.HandleFunc("GET /admin/publishers", a.guard(a.publishers))
	mux.HandleFunc("GET /admin/publishers/{id}", a.guard(a.publisher))
	mux.HandleFunc("POST /admin/publishers/{id}/status", a.guard(a.status))
	mux.HandleFunc("POST /admin/publishers/{id}/quota", a.guard(a.quota))
	mux.HandleFunc("POST /admin/keys/{id}/revoke", a.guard(a.revokeKey))
	mux.HandleFunc("GET /admin/servers", a.guard(a.servers))
	mux.HandleFunc("POST /admin/servers/{id}/flags", a.guard(a.flags))
	mux.HandleFunc("GET /admin/peers", a.guard(a.peers))
	mux.HandleFunc("GET /admin/discord", a.guard(a.discordPage))
	mux.HandleFunc("POST /admin/discord", a.guard(a.discordSave))
	mux.HandleFunc("POST /admin/discord/clear-token", a.guard(a.discordClearToken))
	mux.HandleFunc("POST /admin/discord/reconnect", a.guard(a.discordReconnect))
	mux.HandleFunc("GET /admin/audit", a.guard(a.audit))
}

func randomHex(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// keyTokenHash is the setup's admin token's SHA-256 in the database (the
// token itself is shown once, never kept).
const keyTokenHash = "admin.token_hash"

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// hasToken tells whether there is an admin token: MASTER_ADMIN_TOKEN, or
// the setup's.
func (a *Admin) hasToken() (bool, error) {
	if a.M.Config.AdminToken != "" {
		return true, nil
	}
	_, set, err := a.M.Store.Setting(keyTokenHash)
	return set, err
}

func (a *Admin) tokenOK(token string) bool {
	if token == "" {
		return false
	}
	if a.M.Config.AdminToken != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(a.M.Config.AdminToken)) == 1
	}
	stored, set, err := a.M.Store.Setting(keyTokenHash)
	return err == nil && set && subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(stored)) == 1
}

// request is an authorised admin request.
type request struct {
	csrf    string
	bearer  bool
	session *session
}

type handler func(w http.ResponseWriter, r *http.Request, q request)

// guard lets through an admin (session or bearer token), over TLS or from
// loopback, and checks a form post's CSRF token and Origin.
func (a *Admin) guard(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := a.Clients.Of(r)
		if !client.Protected() {
			httpx.Fail(w, http.StatusForbidden, "tls_required", "the admin pages are served over HTTPS only", "")
			return
		}
		if has, err := a.hasToken(); err != nil || !has {
			// (no admin yet: the setup makes the token)
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
				return
			}
			httpx.Fail(w, http.StatusServiceUnavailable, "setup_needed", "the master is not set up yet", "")
			return
		}
		now := a.M.Now()
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			if !a.failures.Available(client.Key()) {
				httpx.Fail(w, http.StatusTooManyRequests, "rate_limited", "too many wrong tokens; wait a few minutes", "")
				return
			}
			if !a.tokenOK(strings.TrimSpace(bearer)) {
				a.failures.Allow(client.Key())
				_ = a.M.Store.Audit("admin", "login-failed", "", "bearer token, from "+client.IP.String())
				httpx.Fail(w, http.StatusUnauthorized, "unauthorized", "not the admin token", "")
				return
			}
			next(w, r, request{bearer: true})
			return
		}
		cookie, err := r.Cookie(cookieName)
		a.mu.Lock()
		var s *session
		if err == nil {
			s = a.sessions[cookie.Value]
			if s != nil && (now.Sub(s.created) > sessionLife || now.Sub(s.used) > sessionIdle) {
				delete(a.sessions, cookie.Value)
				s = nil
			}
			if s != nil {
				s.used = now
			}
		}
		a.mu.Unlock()
		if s == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			httpx.Fail(w, http.StatusUnauthorized, "unauthorized", "log in first", "")
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if err := r.ParseForm(); err != nil || !web.SameOrigin(r, a.Clients) ||
				subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
				httpx.Fail(w, http.StatusForbidden, "csrf", "the form's token or origin is wrong; reload the page", "")
				return
			}
		}
		if !a.M.Named() && r.Method == http.MethodGet && r.URL.Path != "/admin/settings" {
			// (MASTER_ADMIN_TOKEN set, but no name yet)
			http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
			return
		}
		next(w, r, request{csrf: s.csrf, session: s})
	}
}

func (a *Admin) render(w http.ResponseWriter, status int, name, title string, q request, data map[string]any) {
	data["Signed"] = q.csrf != "" || q.bearer
	data["CSRF"] = q.csrf
	if a.Updates != nil && data["Signed"] == true {
		if s := a.Updates.Status(); s.Available && !s.Updating {
			data["UpdateBanner"] = s.Latest.Version
		}
	}
	if q.session != nil {
		a.mu.Lock()
		notice, problem := q.session.notice, q.session.problem
		q.session.notice, q.session.problem = "", ""
		a.mu.Unlock()
		if notice != "" {
			data["Notice"] = notice
		}
		if problem != "" && data["Error"] == nil {
			data["Error"] = problem
		}
	}
	web.Render(w, a.pages[name], status, web.PageFor(a.M, title, data))
}

func (a *Admin) loginForm(w http.ResponseWriter, r *http.Request) {
	if has, err := a.hasToken(); err == nil && !has {
		http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
		return
	}
	a.render(w, http.StatusOK, "login", "Log in", request{}, map[string]any{})
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	client := a.Clients.Of(r)
	if !client.Protected() {
		httpx.Fail(w, http.StatusForbidden, "tls_required", "the admin pages are served over HTTPS only", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !web.SameOrigin(r, a.Clients) {
		a.render(w, http.StatusBadRequest, "login", "Log in", request{}, map[string]any{"Error": "The form was refused."})
		return
	}
	if !a.failures.Available(client.Key()) {
		a.render(w, http.StatusTooManyRequests, "login", "Log in", request{},
			map[string]any{"Error": "Too many tries; wait a few minutes."})
		return
	}
	if !a.tokenOK(r.PostForm.Get("token")) {
		a.failures.Allow(client.Key())
		_ = a.M.Store.Audit("admin", "login-failed", "", "from "+client.IP.String())
		a.render(w, http.StatusUnauthorized, "login", "Log in", request{}, map[string]any{"Error": "Not the admin token."})
		return
	}
	a.startSession(w, client.Secure)
	_ = a.M.Store.Audit("admin", "login", "", "from "+client.IP.String())
	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

// startSession logs the browser in.
func (a *Admin) startSession(w http.ResponseWriter, secure bool) {
	id, now := randomHex(32), a.M.Now()
	a.mu.Lock()
	if len(a.sessions) >= maximumSession {
		var oldest string
		for key, s := range a.sessions {
			if oldest == "" || s.used.Before(a.sessions[oldest].used) {
				oldest = key
			}
		}
		delete(a.sessions, oldest)
	}
	a.sessions[id] = &session{csrf: randomHex(16), created: now, used: now}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/admin/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: secure, MaxAge: int(sessionLife / time.Second)})
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request, q request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/admin/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// done answers an action: back to a page, which shows the notice or the
// error once (kept in the session, not the URL), or JSON for a script.
func (a *Admin) done(w http.ResponseWriter, r *http.Request, q request, back string, err error, notice string) {
	if q.bearer {
		if err != nil {
			var action *core.ActionError
			if errors.As(err, &action) {
				httpx.Fail(w, http.StatusConflict, action.Code, action.Message, "")
			} else {
				httpx.Fail(w, http.StatusInternalServerError, "internal", err.Error(), "")
			}
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "message": notice})
		return
	}
	if q.session != nil {
		a.mu.Lock()
		if err != nil {
			q.session.notice, q.session.problem = "", err.Error()
		} else {
			q.session.notice, q.session.problem = notice, ""
		}
		a.mu.Unlock()
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (a *Admin) applications(w http.ResponseWriter, r *http.Request, q request) {
	status := model.ApplicationPending
	if r.URL.Query().Get("status") == "all" {
		status = ""
	}
	list, err := a.M.Store.Applications(status, 500)
	if err != nil {
		a.render(w, http.StatusInternalServerError, "applications", "Applications", q, map[string]any{"Error": err.Error()})
		return
	}
	a.render(w, http.StatusOK, "applications", "Applications", q, map[string]any{"Applications": list})
}

func (a *Admin) application(w http.ResponseWriter, r *http.Request, q request) {
	app, err := a.M.Store.Application(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	related, _ := a.M.Store.RelatedApplications(app)
	a.render(w, http.StatusOK, "application", "Application "+app.ID, q, map[string]any{
		"Application": app, "Related": related, "DefaultQuota": a.M.Config.DefaultQuota})
}

func (a *Admin) approve(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	quota, _ := strconv.Atoi(r.FormValue("quota"))
	p, err := a.M.Approve(id, quota, "admin")
	notice := ""
	if err == nil {
		notice = "Approved: publisher " + p.ID + "."
	}
	a.done(w, r, q, "/admin/applications/"+id, err, notice)
}

func (a *Admin) deny(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	reason := strings.TrimSpace(r.FormValue("reason"))
	var err error
	if reason == "" {
		err = errors.New("a denial needs a reason")
	} else {
		err = a.M.Deny(id, reason, "admin")
	}
	a.done(w, r, q, "/admin/applications/"+id, err, "Denied.")
}

func (a *Admin) publishers(w http.ResponseWriter, r *http.Request, q request) {
	states, err := a.M.States()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, http.StatusOK, "publishers", "Publishers", q, map[string]any{"Publishers": states})
}

// ServerRow is a server and whether it is listed.
type ServerRow struct {
	Server model.Server
	Listed bool
	Why    string
}

func (a *Admin) serverRows(publisherID string) ([]ServerRow, error) {
	var servers []model.Server
	var err error
	if publisherID != "" {
		servers, err = a.M.Store.PublisherServers(publisherID)
	} else {
		servers, err = a.M.Store.Servers(1000)
	}
	if err != nil {
		return nil, err
	}
	now := a.M.Now()
	states := map[string]*core.PublisherState{}
	var rows []ServerRow
	for _, s := range servers {
		if publisherID != "" && s.PublisherID != publisherID {
			continue
		}
		state, seen := states[s.PublisherID]
		if !seen {
			state, _ = a.M.State(s.PublisherID)
			states[s.PublisherID] = state
		}
		why := a.M.Listable(&s, state, now)
		rows = append(rows, ServerRow{Server: s, Listed: why == "", Why: why})
	}
	return rows, nil
}

func (a *Admin) publisher(w http.ResponseWriter, r *http.Request, q request) {
	state, err := a.M.State(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := a.serverRows(state.Publisher.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, http.StatusOK, "publisher", state.Publisher.Name, q, map[string]any{
		"State": state, "Servers": rows})
}

func (a *Admin) status(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	status := r.FormValue("status")
	err := a.M.SetStatus(id, status, strings.TrimSpace(r.FormValue("reason")), "admin")
	a.done(w, r, q, "/admin/publishers/"+id, err, "Status set: "+status+".")
}

func (a *Admin) quota(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	quota, _ := strconv.Atoi(r.FormValue("quota"))
	err := a.M.SetQuota(id, quota, "admin")
	a.done(w, r, q, "/admin/publishers/"+id, err, "Quota set.")
}

func (a *Admin) revokeKey(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	err := a.M.RevokeKey(id, strings.TrimSpace(r.FormValue("reason")), "admin")
	back := "/admin/publishers"
	if p := r.FormValue("publisher"); p != "" && !strings.ContainsAny(p, "/?#") {
		back += "/" + p
	}
	a.done(w, r, q, back, err, "Key "+id+" revoked.")
}

func (a *Admin) servers(w http.ResponseWriter, r *http.Request, q request) {
	rows, err := a.serverRows("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	since := a.M.Now().Unix() - 7*86400
	taken, err := a.M.Store.AuditActions("listing-taken", since, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	takenOver, err := a.M.Store.AuditActions("listing-taken-over", since, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, http.StatusOK, "servers", "Servers", q, map[string]any{"Servers": rows, "Taken": taken,
		"TakenOver": takenOver})
}

func (a *Admin) flags(w http.ResponseWriter, r *http.Request, q request) {
	id := r.PathValue("id")
	hidden, trusted := r.FormValue("hidden") == "1", r.FormValue("trusted") == "1"
	err := a.M.SetServerFlags(id, hidden, strings.TrimSpace(r.FormValue("reason")), trusted, "admin")
	a.done(w, r, q, "/admin/servers", err, "Server "+id+" set.")
}

// PeerRow is a peer and how its synchronisation goes.
type PeerRow struct {
	URL, KeyID, LastError string
	Trusted               bool
	LastOK                int64
}

func (a *Admin) peers(w http.ResponseWriter, r *http.Request, q request) {
	var rows []PeerRow
	for _, p := range a.M.Peers {
		state, _ := a.M.Store.Peer(p.KeyID)
		rows = append(rows, PeerRow{URL: p.URL, KeyID: p.KeyID, Trusted: a.M.TrustedPeer(p.KeyID),
			LastOK: state.LastOK, LastError: state.LastError})
	}
	a.render(w, http.StatusOK, "peers", "Peers", q, map[string]any{"Peers": rows,
		"Interval": a.M.Config.PeersInterval.String()})
}

func (a *Admin) audit(w http.ResponseWriter, r *http.Request, q request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := a.M.Store.AuditLog(200, before)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{"Entries": entries}
	if len(entries) == 200 {
		data["Older"] = entries[len(entries)-1].N
	}
	a.render(w, http.StatusOK, "audit", "Audit log", q, data)
}

// discordPage shows the Discord bot's settings (never its token: only
// whether one is set) and its state.
func (a *Admin) discordPage(w http.ResponseWriter, r *http.Request, q request) {
	data := map[string]any{}
	if a.Discord == nil {
		data["Error"] = "This master runs no Discord bot."
		a.render(w, http.StatusOK, "discord", "Discord", q, data)
		return
	}
	settings, err := a.Discord.Settings()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["TokenSet"] = settings.Token != ""
	data["Guild"], data["Channel"], data["Invite"] = settings.Guild, settings.Channel, settings.Invite
	data["Roles"] = strings.Join(settings.Roles, ", ")
	data["FromEnv"] = settings.FromEnv
	data["State"] = a.Discord.State()
	data["AddURL"] = a.Discord.AddURL()
	a.render(w, http.StatusOK, "discord", "Discord", q, data)
}

func (a *Admin) discordSave(w http.ResponseWriter, r *http.Request, q request) {
	if a.Discord == nil {
		a.done(w, r, q, "/admin/discord", errors.New("this master runs no Discord bot"), "")
		return
	}
	err := a.Discord.Save(discord.Form{Token: r.FormValue("token"), Guild: r.FormValue("guild"),
		Invite: r.FormValue("invite")}, "admin")
	a.done(w, r, q, "/admin/discord", err, "Saved; the bot connects again.")
}

func (a *Admin) discordClearToken(w http.ResponseWriter, r *http.Request, q request) {
	if a.Discord == nil {
		a.done(w, r, q, "/admin/discord", errors.New("this master runs no Discord bot"), "")
		return
	}
	settings, err := a.Discord.Settings()
	if err == nil {
		err = a.Discord.Save(discord.Form{ClearToken: true, Guild: settings.Guild, Invite: settings.Invite}, "admin")
	}
	a.done(w, r, q, "/admin/discord", err, "The token is cleared; the bot is off.")
}

func (a *Admin) discordReconnect(w http.ResponseWriter, r *http.Request, q request) {
	if a.Discord == nil {
		a.done(w, r, q, "/admin/discord", errors.New("this master runs no Discord bot"), "")
		return
	}
	_ = a.M.Store.Audit("admin", "discord-reconnect", "", "")
	a.Discord.Restart()
	a.done(w, r, q, "/admin/discord", nil, "The bot connects again.")
}
