package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a-h/templ"

	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/view"
)

// profile is the master's name and contact, as the setup and the settings
// show them.
type profile struct {
	Name, Contact string
	// the fields the environment sets: "name", "contact"
	FromEnv map[string]bool
}

// setupView is the setup page: its form (with the link's code), or the
// admin token it made.
type setupView struct {
	profile
	Code, Token string
}

// discordView is the Discord page: the bot's state and its settings (never
// its token: only whether one is set).
type discordView struct {
	// a bot runs
	Available                             bool
	State                                 discord.State
	TokenSet                              bool
	Guild, Channel, Invite, Roles, AddURL string
	// the settings the environment sets
	FromEnv map[string]bool
	// the player links: the OAuth2 client secret set, the client's id, the
	// redirect URI, and whether MASTER_PUBLIC_URL is set
	SecretSet bool
	ClientID  string
	Redirect  string
	PublicURL bool
}

// linksReady tells whether the player links are set up.
func linksReady(d discordView) bool { return d.SecretSet && d.ClientID != "" && d.PublicURL }

func secretHint(d discordView) string {
	switch {
	case d.FromEnv["secret"]:
		return "Set by the environment (MASTER_DISCORD_CLIENT_SECRET)."
	case d.SecretSet:
		return "A client secret is set. It is never shown again; type a new one to replace it."
	}
	return "None is set: the player links are off. The Developer Portal's OAuth2 page, Client Secret (Reset Secret)."
}

func secretPlaceholder(d discordView) string {
	switch {
	case d.FromEnv["secret"]:
		return "set by MASTER_DISCORD_CLIENT_SECRET"
	case d.SecretSet:
		return "set (leave empty to keep it)"
	}
	return "not set"
}

// urlQuery escapes a query's value.
func urlQuery(text string) string { return url.QueryEscape(text) }

// envNote says a setting is the environment's (empty if not).
func envNote(fromEnv bool, variable string) string {
	if fromEnv {
		return "Set by the environment (" + variable + "). "
	}
	return ""
}

func tokenHint(d discordView) string {
	switch {
	case d.FromEnv["token"]:
		return "Set by the environment (MASTER_DISCORD_TOKEN). The Developer Portal's Bot page, Reset Token."
	case d.TokenSet:
		return "A token is set. It is never shown again; type a new one to replace it. The Developer Portal's " +
			"Bot page, Reset Token."
	}
	return "No token is set: the bot is off. The Developer Portal's Bot page, Reset Token."
}

func tokenPlaceholder(d discordView) string {
	switch {
	case d.FromEnv["token"]:
		return "set by MASTER_DISCORD_TOKEN"
	case d.TokenSet:
		return "set (leave empty to keep it)"
	}
	return "not set"
}

// page fills a page's common fields for a request: the session's CSRF
// token, the navigation's section, a newer release, and the outcome of the
// session's last action (shown once).
func (a *Admin) page(title, section string, q request) view.Page {
	p := view.For(a.M, title)
	p.Signed, p.CSRF, p.Section = q.csrf != "" || q.bearer, q.csrf, section
	if a.Updates != nil && p.Signed {
		if s := a.Updates.Status(); s.Available && !s.Updating {
			p.UpdateBanner = s.Latest.Version
		}
	}
	if q.session != nil {
		a.mu.Lock()
		p.Notice, p.Error = q.session.notice, q.session.problem
		q.session.notice, q.session.problem = "", ""
		a.mu.Unlock()
	}
	return p
}

// show writes a page.
func show(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	view.Render(w, r, status, c)
}

// roles writes the approver roles.
func roles(list []string) string { return strings.Join(list, ", ") }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// count writes a number with its thousands apart: 396,104,512.
func count(n uint64) string {
	text := strconv.FormatUint(n, 10)
	for i := len(text) - 3; i > 0; i -= 3 {
		text = text[:i] + "," + text[i:]
	}
	return text
}
