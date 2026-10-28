package admin

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
)

// netlistView is the Netlist page: the list served, the build held, the
// sources, the admin's settings, and an address looked up.
type netlistView struct {
	// the builder runs (MASTER_NETLIST)
	Enabled     bool
	Status      netlist.Status
	Policy      map[string]string
	Address     string
	Lookup      *netlist.Lookup
	LookupError string
	Interval    string
	TorInterval string
}

func (a *Admin) netlistView(r *http.Request, policy map[string]string) (netlistView, error) {
	v := netlistView{Enabled: a.Netlist != nil, Interval: a.M.Config.NetlistInterval.String(),
		TorInterval: a.M.Config.NetlistTorInterval.String()}
	if a.Netlist == nil {
		return v, nil
	}
	v.Status = a.Netlist.Status()
	var err error
	if policy == nil {
		if policy, err = a.Netlist.Policy(); err != nil {
			return v, err
		}
	}
	v.Policy = policy
	if v.Address = strings.TrimSpace(r.URL.Query().Get("ip")); v.Address != "" {
		address, err := netip.ParseAddr(v.Address)
		if err != nil {
			v.LookupError = "Not an address: an IPv4 address, such as 203.0.113.7."
		} else if l, err := a.Netlist.Lookup(address); err != nil {
			v.LookupError = err.Error()
		} else {
			v.Lookup = &l
		}
	}
	return v, nil
}

func (a *Admin) netlistPage(w http.ResponseWriter, r *http.Request, q request) {
	p := a.page("Netlist", "netlist", q)
	v, err := a.netlistView(r, nil)
	if err != nil {
		p.Error = err.Error()
	}
	show(w, r, http.StatusOK, netlistPage(p, v))
}

func (a *Admin) netlistRebuild(w http.ResponseWriter, r *http.Request, q request) {
	if a.Netlist == nil {
		a.done(w, r, q, "/admin/netlist", errors.New("this master builds no netlist (MASTER_NETLIST=off)"), "")
		return
	}
	a.Netlist.Rebuild("admin")
	a.done(w, r, q, "/admin/netlist", nil, "The sources are being fetched and the list built: reload the page in "+
		"a minute.")
}

func (a *Admin) netlistPublish(w http.ResponseWriter, r *http.Request, q request) {
	if a.Netlist == nil {
		a.done(w, r, q, "/admin/netlist", errors.New("this master builds no netlist (MASTER_NETLIST=off)"), "")
		return
	}
	p, err := a.Netlist.PublishHeld("admin")
	notice := ""
	if err == nil {
		notice = "Published: serial " + itoa(int64(p.Serial)) + "."
	}
	a.done(w, r, q, "/admin/netlist", err, notice)
}

func (a *Admin) netlistPolicy(w http.ResponseWriter, r *http.Request, q request) {
	if a.Netlist == nil {
		a.done(w, r, q, "/admin/netlist", errors.New("this master builds no netlist (MASTER_NETLIST=off)"), "")
		return
	}
	texts := map[string]string{}
	for _, key := range netlist.PolicyKeys {
		texts[key] = r.FormValue(key)
	}
	err := a.Netlist.SetPolicy(texts, "admin")
	if err != nil && !q.bearer {
		// (the page again, with what was typed, rather than lose it)
		p := a.page("Netlist", "netlist", q)
		p.Error = err.Error()
		v, verr := a.netlistView(r, texts)
		if verr != nil {
			p.Error += "; " + verr.Error()
		}
		show(w, r, http.StatusBadRequest, netlistPage(p, v))
		return
	}
	a.done(w, r, q, "/admin/netlist", err, "Saved: the list is being built again.")
}
