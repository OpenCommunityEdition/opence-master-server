package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/view"
)

// The player links' pages (docs/master_protocol.md, "Linking"): /link takes
// the game's signed query and sends the player to Discord's OAuth2,
// /link/callback takes Discord's answer and records the link, and
// /link/manage lists a Discord account's keys and unlinks them.

const (
	// the link page's cookie: the OAuth state, which Discord's answer must
	// carry
	linkCookie = "opence_link"
	// the manage page's session
	manageCookie = "opence_link_manage"
	manageLife   = 15 * time.Minute
	// the manage sessions held at most
	maximumManage = 1024
)

// Linking is what the link pages take of the Discord bot: the OAuth2
// client's id and secret, the bot's token and server.
type Linking interface {
	LinkSettings() discord.LinkSettings
}

// manageSession is a Discord account logged in to /link/manage.
type manageSession struct {
	discordID, name, csrf string
	created               time.Time
	notice                string
}

// linkSetup returns the links' settings and the redirect URI, or what is
// missing (the fix named).
func (p *Pages) linkSetup() (discord.LinkSettings, string, []string) {
	var s discord.LinkSettings
	if p.Linking != nil {
		s = p.Linking.LinkSettings()
	}
	var missing []string
	if p.M.Config.PublicURL == "" {
		missing = append(missing, "set MASTER_PUBLIC_URL to the master's public https:// origin")
	}
	if s.ClientID == "" {
		missing = append(missing, "set the Discord bot's token on the admin pages' Discord page (its application "+
			"is the OAuth2 client), or MASTER_DISCORD_CLIENT_ID")
	}
	if s.ClientSecret == "" {
		missing = append(missing, "set MASTER_DISCORD_CLIENT_SECRET, or the client secret on the admin pages' "+
			"Discord page (the Developer Portal's OAuth2 page, Client Secret)")
	}
	if len(missing) > 0 {
		missing = append(missing, "add the redirect URI "+p.redirectURI()+" in the Discord Developer Portal "+
			"(the application's OAuth2 page, Redirects)")
	}
	return s, p.redirectURI(), missing
}

func (p *Pages) redirectURI() string {
	base := p.M.Config.PublicURL
	if base == "" {
		base = "<MASTER_PUBLIC_URL>"
	}
	return base + "/link/callback"
}

// linkGate answers a link page's request that may not go on: plain HTTP
// from beyond loopback, or past the address's limit. False then.
func (p *Pages) linkGate(w http.ResponseWriter, r *http.Request) bool {
	client := p.Clients.Of(r)
	if !client.Protected() {
		p.message(w, r, http.StatusForbidden, "HTTPS only", Message{Heading: "This page is served over HTTPS only",
			Lines: []string{"Open it with https:// (the master's MASTER_PUBLIC_URL)."}})
		return false
	}
	if allowed, wait := p.linkLimit.Allow(client.Key()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		p.message(w, r, http.StatusTooManyRequests, "Too many requests", Message{Heading: "Too many requests",
			Lines: []string{"Wait a minute and try again."}})
		return false
	}
	return true
}

func (p *Pages) notSetUp(w http.ResponseWriter, r *http.Request, missing []string) {
	lines := []string{"This master's admins have not set up the Discord links yet. To set them up:"}
	for _, m := range missing {
		lines = append(lines, "- "+m+".")
	}
	p.message(w, r, http.StatusServiceUnavailable, "Linking is not set up", Message{
		Heading: "Linking is not set up on this master", Lines: lines})
}

func randomState() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// setLinkCookie sets (or, with an empty value, clears) a link page's cookie.
func setLinkCookie(w http.ResponseWriter, name, value string, secure bool, life time.Duration) {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/link", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: secure, MaxAge: int(life / time.Second)}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
}

// link takes the game's signed query, records the visit, and shows the
// confirmation code with the way to Discord.
func (p *Pages) link(w http.ResponseWriter, r *http.Request) {
	if !p.linkGate(w, r) {
		return
	}
	settings, redirect, missing := p.linkSetup()
	if len(missing) > 0 {
		p.notSetUp(w, r, missing)
		return
	}
	q := r.URL.Query()
	query, err := sign.ParsePlayerQuery(q.Get("key"), q.Get("ts"), q.Get("sig"))
	now := p.M.Now()
	if err == nil {
		err = query.Check(sign.LinkLabel, p.M.KeyID, now, sign.LinkWindow)
	}
	switch {
	case errors.Is(err, sign.ErrClock):
		p.message(w, r, http.StatusUnauthorized, "Link expired", Message{Heading: "This link has expired",
			Lines: []string{"Start again from the game: it makes a new link each time.",
				"If it keeps happening, the clock of the device running the game is wrong: set it to the right " +
					"time (this master's is " + view.TimeText(now.Unix()) + ").", "(clock)"}})
		return
	case errors.Is(err, sign.ErrSmallOrder):
		p.message(w, r, http.StatusUnauthorized, "Bad link", Message{Heading: "This link is not valid",
			Lines: []string{"The game's player key cannot be linked. Delete player.key beside config.toml and " +
				"start again from the game.", "(bad_signature)"}})
		return
	case err != nil:
		p.message(w, r, http.StatusUnauthorized, "Bad link", Message{Heading: "This link is not valid",
			Lines: []string{"Start again from the game: open the link it gives, whole.", "(bad_signature)"}})
		return
	}
	code := sign.LinkCode(query.Key, query.TS)
	state := randomState()
	if err := p.M.Store.AddPendingLink(store.PendingLink{State: state, Kind: store.PendingLinkKey,
		Key: query.KeyHex, TS: query.Time, Code: code, Created: now.Unix()}); err != nil {
		p.message(w, r, http.StatusInternalServerError, "Error", Message{Heading: "The master failed",
			Lines: []string{"Try again in a moment."}})
		return
	}
	setLinkCookie(w, linkCookie, state, p.Clients.Of(r).Secure, store.LinkPendingRetention)
	page := view.For(p.M, "Link Discord")
	page.Section = "link"
	view.Render(w, r, http.StatusOK, linkPage(page, code, sign.KeyID(query.Key),
		p.OAuth.AuthorizeURL(settings.ClientID, redirect, state)))
}

// callback takes Discord's answer: the state must be the visit's (and the
// browser's cookie), the code gives the account, and the master's rules
// decide.
func (p *Pages) callback(w http.ResponseWriter, r *http.Request) {
	if !p.linkGate(w, r) {
		return
	}
	settings, redirect, missing := p.linkSetup()
	if len(missing) > 0 {
		p.notSetUp(w, r, missing)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie(linkCookie)
	secure := p.Clients.Of(r).Secure
	setLinkCookie(w, linkCookie, "", secure, 0)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		p.message(w, r, http.StatusBadRequest, "Start again", Message{Heading: "This sign-in is not this browser's",
			Lines: []string{"Start again from the game, in the browser it opens (the page needs its cookie: " +
				"cookies must be allowed for this site)."}})
		return
	}
	now := p.M.Now()
	pending, err := p.M.Store.TakePendingLink(state, now.Add(-store.LinkPendingRetention).Unix())
	if err != nil {
		p.message(w, r, http.StatusBadRequest, "Start again", Message{Heading: "This sign-in has expired",
			Lines: []string{"It is good for 10 minutes, once. Start again from the game (or from /link/manage)."}})
		return
	}
	if e := q.Get("error"); e != "" {
		p.message(w, r, http.StatusOK, "Not linked", Message{Heading: "Nothing was linked",
			Lines: []string{"Discord did not authorise it (" + clip(e, 40) + "). To link, start again from the game."}})
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 200 {
		p.message(w, r, http.StatusBadRequest, "Start again", Message{Heading: "Discord's answer is incomplete",
			Lines: []string{"Start again from the game."}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := p.OAuth.Identify(ctx, settings.ClientID, settings.ClientSecret, code, redirect)
	if err != nil {
		p.M.Log.Warn("link: Discord's OAuth2 failed", "err", err)
		p.message(w, r, http.StatusBadGateway, "Discord failed", Message{Heading: "Discord did not answer as it should",
			Lines: []string{"Try again from the game in a moment. If it keeps failing, tell the master's admins " +
				"(the master's log says why)."}})
		return
	}
	if pending.Kind == store.PendingLinkManage {
		p.startManage(w, user, secure)
		http.Redirect(w, r, "/link/manage", http.StatusSeeOther)
		return
	}
	if revoked, err := p.M.Revoked(user.ID); err != nil {
		p.failed(w, r)
		return
	} else if revoked != nil {
		p.message(w, r, http.StatusForbidden, "Revoked", Message{Heading: "This Discord account may not link here",
			Lines: []string{"This master's admins revoked it: " + revoked.Reason + "."}})
		return
	}
	if days := p.M.Config.LinkMinAccountDays; days > 0 {
		id, _ := strconv.ParseUint(user.ID, 10, 64)
		age := now.Sub(time.UnixMilli(core.DiscordCreated(id)))
		if age < time.Duration(days)*24*time.Hour {
			p.message(w, r, http.StatusForbidden, "Too new", Message{Heading: "This Discord account is too new",
				Lines: []string{fmt.Sprintf("This master links Discord accounts %d days old or more; this one is %d "+
					"days old. Try again later, or with an older account.", days, int(age/(24*time.Hour)))}})
			return
		}
	}
	flags := 0
	if settings.Guild != "" && settings.BotToken != "" {
		member, err := p.OAuth.Member(ctx, settings.BotToken, settings.Guild, user.ID)
		switch {
		case err != nil && p.M.Config.LinkRequireGuild:
			p.M.Log.Warn("link: the membership check failed", "err", err)
			p.message(w, r, http.StatusBadGateway, "Discord failed", Message{
				Heading: "The Discord server's membership could not be checked",
				Lines:   []string{"Try again from the game in a moment."}})
			return
		case err != nil:
			p.M.Log.Debug("link: the membership check failed", "err", err)
		case member:
			flags |= sign.PassFlagGuild
		}
	}
	if p.M.Config.LinkRequireGuild && flags&sign.PassFlagGuild == 0 {
		m := Message{Heading: "Join the Discord server first",
			Lines: []string{"This master links the members of its Discord server only. Join it, then start again " +
				"from the game."}}
		if settings.Invite != "" {
			m.Action = Action{Href: settings.Invite, Text: "Join the Discord server"}
		}
		p.message(w, r, http.StatusForbidden, "Not a member", m)
		return
	}
	key, _ := hex.DecodeString(pending.Key)
	err = p.M.SaveLink(key, user.ID, user.Name, flags, "discord:"+user.ID+" "+user.Name)
	var revoked *core.RevokedError
	if errors.As(err, &revoked) {
		p.message(w, r, http.StatusForbidden, "Revoked", Message{Heading: "This Discord account may not link here",
			Lines: []string{revoked.Error() + "."}})
		return
	} else if err != nil {
		p.failed(w, r)
		return
	}
	page := view.For(p.M, "Linked")
	page.Section = "link"
	view.Render(w, r, http.StatusOK, linkedPage(page, user.Name, pending.Code))
}

func (p *Pages) failed(w http.ResponseWriter, r *http.Request) {
	p.message(w, r, http.StatusInternalServerError, "Error", Message{Heading: "The master failed",
		Lines: []string{"Try again in a moment."}})
}

func clip(text string, n int) string {
	if len(text) > n {
		return text[:n]
	}
	return text
}

// startManage logs a Discord account in to /link/manage.
func (p *Pages) startManage(w http.ResponseWriter, user discord.User, secure bool) {
	id, now := randomState()+randomState(), p.M.Now()
	p.manageMu.Lock()
	for key, s := range p.manage {
		if now.Sub(s.created) > manageLife {
			delete(p.manage, key)
		}
	}
	if len(p.manage) >= maximumManage {
		var oldest string
		for key, s := range p.manage {
			if oldest == "" || s.created.Before(p.manage[oldest].created) {
				oldest = key
			}
		}
		delete(p.manage, oldest)
	}
	p.manage[id] = &manageSession{discordID: user.ID, name: user.Name, csrf: randomState(), created: now}
	p.manageMu.Unlock()
	setLinkCookie(w, manageCookie, id, secure, manageLife)
}

// manageSessionOf is the request's manage session (nil for none).
func (p *Pages) manageSessionOf(r *http.Request) (*manageSession, string) {
	cookie, err := r.Cookie(manageCookie)
	if err != nil {
		return nil, ""
	}
	p.manageMu.Lock()
	defer p.manageMu.Unlock()
	s := p.manage[cookie.Value]
	if s != nil && p.M.Now().Sub(s.created) > manageLife {
		delete(p.manage, cookie.Value)
		s = nil
	}
	return s, cookie.Value
}

// manageView is what /link/manage shows.
type manageView struct {
	Name, DiscordID, CSRF, Notice string
	Links                         []store.Link
}

func (p *Pages) manageGet(w http.ResponseWriter, r *http.Request) {
	if !p.Clients.Of(r).Protected() {
		p.linkGate(w, r)
		return
	}
	page := view.For(p.M, "Your linked keys")
	page.Section = "link"
	s, _ := p.manageSessionOf(r)
	if s == nil {
		_, _, missing := p.linkSetup()
		view.Render(w, r, http.StatusOK, manageLoginPage(page, len(missing) == 0))
		return
	}
	links, err := p.M.Store.AccountLinks(s.discordID)
	if err != nil {
		p.failed(w, r)
		return
	}
	p.manageMu.Lock()
	v := manageView{Name: s.name, DiscordID: s.discordID, CSRF: s.csrf, Notice: s.notice, Links: links}
	s.notice = ""
	p.manageMu.Unlock()
	view.Render(w, r, http.StatusOK, managePage(page, v))
}

// manageLogin sends the player to Discord to log in to /link/manage.
func (p *Pages) manageLogin(w http.ResponseWriter, r *http.Request) {
	if !p.linkGate(w, r) {
		return
	}
	settings, redirect, missing := p.linkSetup()
	if len(missing) > 0 {
		p.notSetUp(w, r, missing)
		return
	}
	state := randomState()
	if err := p.M.Store.AddPendingLink(store.PendingLink{State: state, Kind: store.PendingLinkManage,
		Created: p.M.Now().Unix()}); err != nil {
		p.failed(w, r)
		return
	}
	setLinkCookie(w, linkCookie, state, p.Clients.Of(r).Secure, store.LinkPendingRetention)
	http.Redirect(w, r, p.OAuth.AuthorizeURL(settings.ClientID, redirect, state), http.StatusSeeOther)
}

// managePost checks a manage form: the session, its CSRF token and the
// Origin; nil (answered) otherwise.
func (p *Pages) managePost(w http.ResponseWriter, r *http.Request) (*manageSession, string) {
	if !p.Clients.Of(r).Protected() {
		p.linkGate(w, r)
		return nil, ""
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	s, id := p.manageSessionOf(r)
	if s == nil {
		http.Redirect(w, r, "/link/manage", http.StatusSeeOther)
		return nil, ""
	}
	if err := r.ParseForm(); err != nil || !SameOrigin(r, p.Clients) ||
		subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
		p.message(w, r, http.StatusForbidden, "Refused", Message{Heading: "The form was refused",
			Lines: []string{"Reload the page and try again."}})
		return nil, ""
	}
	return s, id
}

func (p *Pages) manageUnlink(w http.ResponseWriter, r *http.Request) {
	s, _ := p.managePost(w, r)
	if s == nil {
		return
	}
	err := p.M.Unlink(r.PostForm.Get("key"), s.discordID, "discord:"+s.discordID+" "+s.name)
	p.manageMu.Lock()
	if err != nil {
		s.notice = "That key is not linked to this account."
	} else {
		s.notice = "Unlinked: that game's player key gets no pass from now on."
	}
	p.manageMu.Unlock()
	http.Redirect(w, r, "/link/manage", http.StatusSeeOther)
}

func (p *Pages) manageDelete(w http.ResponseWriter, r *http.Request) {
	s, id := p.managePost(w, r)
	if s == nil {
		return
	}
	n, err := p.M.UnlinkAccount(s.discordID, "discord:"+s.discordID+" "+s.name)
	if err != nil {
		p.failed(w, r)
		return
	}
	p.manageMu.Lock()
	delete(p.manage, id)
	p.manageMu.Unlock()
	setLinkCookie(w, manageCookie, "", p.Clients.Of(r).Secure, 0)
	p.message(w, r, http.StatusOK, "Deleted", Message{Heading: "Everything is deleted",
		Lines: []string{fmt.Sprintf("This master holds nothing of your Discord account any more (%d %s unlinked).",
			n, view.Plural(n, "key", "keys")), "A game that linked it gets no new pass; its pass runs out within " +
			p.M.Config.PassTTL.String() + "."}})
}

func (p *Pages) manageLogout(w http.ResponseWriter, r *http.Request) {
	s, id := p.managePost(w, r)
	if s == nil {
		return
	}
	p.manageMu.Lock()
	delete(p.manage, id)
	p.manageMu.Unlock()
	setLinkCookie(w, manageCookie, "", p.Clients.Of(r).Secure, 0)
	http.Redirect(w, r, "/link/manage", http.StatusSeeOther)
}

// privacy is what the master keeps, and the netlist's sources and their
// licences.
func (p *Pages) privacy(w http.ResponseWriter, r *http.Request) {
	page := view.For(p.M, "Privacy")
	page.Section = "privacy"
	view.Render(w, r, http.StatusOK, privacyPage(page, p.M.Config.PassTTL.String()))
}

// manageMu guards the manage sessions.
type manageSessions struct {
	manageMu sync.Mutex
	manage   map[string]*manageSession
}
