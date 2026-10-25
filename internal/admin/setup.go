package admin

// The first launch's setup: a master with no admin token prints a setup
// link to its log (SetupCode); whoever opens it names the master, gives
// the contact if they like, and is shown the admin token once, which the
// master keeps only a hash of. The settings page changes the name and the
// contact afterwards.

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/update"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

// SetupCode is the setup link's code (/admin/setup?code=...), while the
// master has no admin token; empty once it has one.
func (a *Admin) SetupCode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setupCode
}

func (a *Admin) codeOK(code string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setupCode != "" && subtle.ConstantTimeCompare([]byte(code), []byte(a.setupCode)) == 1
}

func (a *Admin) setupData(name, contact string) map[string]any {
	p := a.M.Profile()
	if name == "" {
		name = p.Name
	}
	if contact == "" {
		contact = p.Contact
	}
	return map[string]any{"Name": name, "Contact": contact, "FromEnv": p.FromEnv}
}

func (a *Admin) setupPage(w http.ResponseWriter, r *http.Request) {
	if a.SetupCode() == "" {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	if !a.Clients.Of(r).Protected() {
		httpx.Fail(w, http.StatusForbidden, "tls_required", "the admin pages are served over HTTPS only", "")
		return
	}
	data := a.setupData("", "")
	if code := r.URL.Query().Get("code"); a.codeOK(code) {
		data["Code"] = code
	}
	a.render(w, http.StatusOK, "setup", "Set up", request{}, data)
}

func (a *Admin) setup(w http.ResponseWriter, r *http.Request) {
	client := a.Clients.Of(r)
	if !client.Protected() {
		httpx.Fail(w, http.StatusForbidden, "tls_required", "the admin pages are served over HTTPS only", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !web.SameOrigin(r, a.Clients) {
		a.render(w, http.StatusBadRequest, "setup", "Set up", request{}, map[string]any{"Error": "The form was refused."})
		return
	}
	if a.SetupCode() == "" {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if !a.failures.Available(client.Key()) {
		a.render(w, http.StatusTooManyRequests, "setup", "Set up", request{},
			map[string]any{"Error": "Too many tries; wait a few minutes."})
		return
	}
	code, name, contact := r.PostForm.Get("code"), r.PostForm.Get("name"), r.PostForm.Get("contact")
	if !a.codeOK(code) {
		a.failures.Allow(client.Key())
		_ = a.M.Store.Audit("admin", "setup-failed", "", "from "+client.IP.String())
		a.render(w, http.StatusForbidden, "setup", "Set up", request{},
			map[string]any{"Error": "Not this master's setup link. Open the link in its log."})
		return
	}
	data := a.setupData(name, contact)
	data["Code"] = code
	if err := a.M.SetProfile(name, contact, "admin"); err != nil {
		data["Error"] = setupError(err)
		a.render(w, http.StatusBadRequest, "setup", "Set up", request{}, data)
		return
	}
	// (the code is claimed once: a second form sent with it is refused)
	a.mu.Lock()
	claimed := a.setupCode == code && code != ""
	a.setupCode = ""
	a.mu.Unlock()
	if !claimed {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	token := randomHex(32)
	if err := a.M.Store.SetSetting(keyTokenHash, hashToken(token)); err != nil {
		a.mu.Lock()
		a.setupCode = code
		a.mu.Unlock()
		data["Error"] = "The admin token could not be stored: " + err.Error()
		a.render(w, http.StatusInternalServerError, "setup", "Set up", request{}, data)
		return
	}
	_ = a.M.Store.Audit("admin", "setup", "", "from "+client.IP.String())
	a.startSession(w, client.Secure)
	a.render(w, http.StatusOK, "setup", "Set up", request{}, map[string]any{"Token": token})
}

func setupError(err error) string {
	var field *core.FieldError
	if errors.As(err, &field) {
		label := map[string]string{"name": "Name", "contact": "Contact"}[field.Field]
		return label + ": " + field.Message + "."
	}
	return err.Error()
}

func (a *Admin) settingsPage(w http.ResponseWriter, r *http.Request, q request) {
	data := a.setupData("", "")
	if a.Updates != nil {
		data["Updates"] = a.Updates.Status()
	}
	if !a.M.Named() {
		data["Error"] = "Name the master first: its name is shown in its lists, its pages and the Discord bot's messages."
	}
	a.render(w, http.StatusOK, "settings", "Settings", q, data)
}

func (a *Admin) settingsSave(w http.ResponseWriter, r *http.Request, q request) {
	err := a.M.SetProfile(r.FormValue("name"), r.FormValue("contact"), "admin")
	if err != nil {
		err = errors.New(setupError(err))
	}
	a.done(w, r, q, "/admin/settings", err, "Saved.")
}

func (a *Admin) updateCheck(w http.ResponseWriter, r *http.Request, q request) {
	if a.Updates == nil {
		a.done(w, r, q, "/admin/settings", errors.New("this master has no updater"), "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	release, err := a.Updates.Check(ctx)
	notice := "The latest release is " + release.Version + ": this master runs it."
	if err == nil && update.Newer(release.Version, a.Updates.Current) {
		notice = "Release " + release.Version + " is out."
	}
	a.done(w, r, q, "/admin/settings", err, notice)
}

func (a *Admin) updateStart(w http.ResponseWriter, r *http.Request, q request) {
	if a.Updates == nil {
		a.done(w, r, q, "/admin/settings", errors.New("this master has no updater"), "")
		return
	}
	err := a.Updates.Start("admin")
	a.done(w, r, q, "/admin/settings", err, "The update started: the master restarts on its own in a moment; "+
		"reload this page.")
}
