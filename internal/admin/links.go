package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// linksView is the Links page: the links found, and the revoked accounts.
type linksView struct {
	Query   string
	Links   []store.Link
	Revoked []store.Revocation
	// the pass's time, and MASTER_LINK_MAX_KEYS
	PassTTL string
	MaxKeys int
}

func (a *Admin) links(w http.ResponseWriter, r *http.Request, q request) {
	p := a.page("Links", "links", q)
	v := linksView{Query: strings.TrimSpace(r.URL.Query().Get("q")), PassTTL: a.M.Config.PassTTL.String(),
		MaxKeys: a.M.Config.LinkMaxKeys}
	var err error
	if v.Links, err = a.M.Store.SearchLinks(v.Query, 200); err != nil {
		p.Error = err.Error()
	}
	if v.Revoked, err = a.M.Store.Revocations(); err != nil {
		p.Error = err.Error()
	}
	show(w, r, http.StatusOK, linksPage(p, v))
}

// back is the Links page, with the search kept.
func linksBack(r *http.Request) string {
	if text := strings.TrimSpace(r.FormValue("q")); text != "" {
		return "/admin/links?q=" + urlQuery(text)
	}
	return "/admin/links"
}

func (a *Admin) unlink(w http.ResponseWriter, r *http.Request, q request) {
	err := a.M.Unlink(strings.TrimSpace(r.FormValue("key")), "", "admin")
	a.done(w, r, q, linksBack(r), err, "Unlinked.")
}

func (a *Admin) revokeLink(w http.ResponseWriter, r *http.Request, q request) {
	id := strings.TrimSpace(r.FormValue("discord_id"))
	n, err := a.M.RevokeAccount(id, r.FormValue("reason"), "admin")
	a.done(w, r, q, linksBack(r), err, "discord:"+id+" revoked ("+strconv.Itoa(n)+" keys unlinked).")
}

func (a *Admin) liftRevocation(w http.ResponseWriter, r *http.Request, q request) {
	id := strings.TrimSpace(r.FormValue("discord_id"))
	err := a.M.LiftRevocation(id, "admin")
	a.done(w, r, q, linksBack(r), err, "discord:"+id+" may link again.")
}
