package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// ListingWindow is how far a listing's own time may be from the master's
// clock (the game's browsers allow as much for a live listing).
const ListingWindow = 3600

// DormantInstances is how many server records a publisher may hold beyond
// its quota (instances closed or not published lately, kept until purged).
const DormantInstances = 16

// BindingStale is how long a server may go on publishing its host's listing
// without a newer one (a higher sequence) before another publisher that
// brings a newer one takes the host key from it. A host makes a new listing
// at each of its publishes (every core.Interval), so a server that holds
// one this long is replaying a copy, or its host is gone.
const BindingStale = 3 * core.Interval

var (
	regionPattern = regexp.MustCompile(`^[a-z0-9-]{0,16}$`)
	serverID      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// PublishBody is a publish's JSON body, read field by field so that a
// field of the wrong type is named.
type PublishBody struct {
	Protocol       int
	Instance       string
	Listing        []byte
	Variant        string
	Dedicated      bool
	Build          string
	Region         string
	TunnelPort     int
	Address        string
	Closed         bool
	Serial         int64
	HasAddress     bool
	HasTunnelPort  bool
	HasListing     bool
	Declared       map[string]any
	UnknownIgnored []string
}

// ParsePublish reads a publish body; on a refusal it returns the field.
func ParsePublish(body []byte) (*PublishBody, string, error) {
	fields, err := decodeObject(body)
	if err != nil {
		return nil, "", err
	}
	p := &PublishBody{Declared: map[string]any{}}
	get := func(name string, target any) (bool, error) {
		raw, ok := fields[name]
		if !ok || string(raw) == "null" {
			return false, nil
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return true, fmt.Errorf("%s has the wrong type", name)
		}
		return true, nil
	}
	type field struct {
		name   string
		target any
	}
	var listingText, address string
	var tunnelPort, protocol float64
	var serial float64
	for _, f := range []field{
		{"protocol", &protocol}, {"instance", &p.Instance}, {"listing", &listingText}, {"variant", &p.Variant},
		{"dedicated", &p.Dedicated}, {"build", &p.Build}, {"region", &p.Region}, {"tunnel_port", &tunnelPort},
		{"address", &address}, {"closed", &p.Closed}, {"serial", &serial},
	} {
		has, err := get(f.name, f.target)
		if err != nil {
			return nil, f.name, err
		}
		switch f.name {
		case "listing":
			p.HasListing = has
		case "tunnel_port":
			p.HasTunnelPort = has
		case "address":
			p.HasAddress = has
		}
	}
	if protocol != float64(core.Protocol) {
		return nil, "protocol", fmt.Errorf("protocol is %d", core.Protocol)
	}
	p.Protocol = core.Protocol
	if !sign.ValidInstance(p.Instance) {
		return nil, "instance", errors.New("instance is 1 to 32 of a-z, 0-9, - and _, not starting with - or _")
	}
	if p.HasListing {
		p.Listing, err = base64.StdEncoding.DecodeString(listingText)
		if err != nil {
			return nil, "listing", errors.New("listing is base64")
		}
	}
	if p.HasTunnelPort {
		if tunnelPort != float64(int(tunnelPort)) || tunnelPort < 1 || tunnelPort > 65535 {
			return nil, "tunnel_port", errors.New("tunnel_port is 1 to 65535")
		}
		p.TunnelPort = int(tunnelPort)
	}
	if p.HasAddress && address != "" {
		parsed, err := netip.ParseAddrPort(address)
		if err != nil || parsed.Port() == 0 || parsed.Addr().Zone() != "" {
			return nil, "address", errors.New("address is an IP address and a port: 203.0.113.5:2302")
		}
		if !netaddr.Global(parsed.Addr()) && !netaddr.Local(parsed.Addr()) {
			return nil, "address", errors.New("address is a globally routable address (or, from the same " +
				"network, a private or loopback one)")
		}
		p.Address = probe.Canonical(parsed)
	} else {
		p.HasAddress = false
	}
	if serial < 0 || serial != float64(int64(serial)) {
		return nil, "serial", errors.New("serial is a whole number, 0 or more")
	}
	p.Serial = int64(serial)
	p.Region = strings.ToLower(p.Region)
	if !regionPattern.MatchString(p.Region) {
		return nil, "region", errors.New("region is up to 16 of a-z, 0-9 and -")
	}
	p.Variant = listing.SanitizeString(p.Variant, listing.GametypeSize)
	p.Build = listing.SanitizeString(p.Build, 32)
	if !p.Closed && !p.HasListing {
		return nil, "listing", errors.New("listing is needed (but with closed: true)")
	}
	if !p.Closed && !p.HasTunnelPort && !p.HasAddress {
		return nil, "tunnel_port", errors.New("tunnel_port (or address) is needed")
	}
	for _, name := range []string{"name", "map", "gametype", "players", "max_players", "teams", "in_progress",
		"password", "network_version"} {
		var value any
		if has, err := get(name, &value); err == nil && has {
			p.Declared[name] = value
		}
	}
	return p, "", nil
}

// contradictions compares what a body says with the listing, which wins.
func contradictions(declared map[string]any, l *listing.Listing) []string {
	actual := map[string]any{
		"name": l.Name, "map": l.Map, "gametype": l.Gametype, "players": float64(l.Players),
		"max_players": float64(l.MaxPlayers), "teams": l.Teams(), "in_progress": l.InProgress(),
		"password": l.Password(), "network_version": float64(l.NetworkVersion),
	}
	var warnings []string
	for _, name := range []string{"name", "map", "gametype", "players", "max_players", "teams", "in_progress",
		"password", "network_version"} {
		value, ok := declared[name]
		if !ok {
			continue
		}
		if fmt.Sprint(value) != fmt.Sprint(actual[name]) {
			warnings = append(warnings, fmt.Sprintf("%s: the listing's %v is used, not %v", name, actual[name], value))
		}
	}
	return warnings
}

// PublishResponse is a publish's answer.
type PublishResponse struct {
	OK              bool     `json:"ok"`
	ServerID        string   `json:"server_id"`
	Listed          bool     `json:"listed"`
	Closed          bool     `json:"closed,omitempty"`
	Interval        int      `json:"interval"`
	TTL             int      `json:"ttl"`
	Probe           string   `json:"probe,omitempty"`
	Reachable       bool     `json:"reachable"`
	ObservedAddress string   `json:"observed_address,omitempty"`
	ProbeAddress    string   `json:"probe_address,omitempty"`
	Hidden          bool     `json:"hidden,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	MasterTime      int64    `json:"master_time"`
}

func (s *Server) count(result string) { s.Metrics.Add("master_publishes_total", result) }

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	recorder := &resultWriter{ResponseWriter: w}
	s.publishHandler(recorder, r)
	s.count(recorder.result)
}

// resultWriter remembers an answer's error code (or ok, pending) for the
// metrics.
type resultWriter struct {
	http.ResponseWriter
	result string
}

func (s *Server) publishHandler(w *resultWriter, r *http.Request) {
	client, ok := s.protected(w, r)
	if !ok {
		return
	}
	if allowed, wait := s.publishAddress.Allow(client.Key()); !allowed {
		s.limited(w, wait, "too many publishes from this address")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	identity := s.authenticate(w, r, body)
	if identity == nil {
		return
	}
	if !s.approved(w, identity) {
		return
	}
	id := r.PathValue("id")
	p, field, err := ParsePublish(body)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "schema", err.Error(), field)
		return
	}
	if !serverID.MatchString(id) || id != sign.ServerID(identity.KeyID, p.Instance) {
		s.fail(w, http.StatusBadRequest, "server_id", "the server id is the first 16 hexadecimal digits of "+
			"SHA-256(key id + instance): "+sign.ServerID(identity.KeyID, p.Instance), "")
		return
	}
	now := s.M.Now()
	existing, err := s.M.Store.Server(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	var l *listing.Listing
	if p.HasListing {
		if l, err = listing.Read(p.Listing); err != nil {
			s.fail(w, http.StatusBadRequest, "listing", err.Error(), "listing")
			return
		}
		if age := now.Unix() - int64(l.Time); age > ListingWindow || age < -ListingWindow {
			s.fail(w, http.StatusBadRequest, "listing", "the listing's time is more than an hour from the "+
				"master's clock", "listing")
			return
		}
	}
	if p.Closed || (l != nil && l.Closed()) {
		if existing != nil && !existing.Closed {
			if err := s.M.Store.CloseServer(id); err != nil {
				s.internal(w, err)
				return
			}
			s.invalidate()
		}
		if s.Prober != nil {
			s.Prober.Remove(id)
		}
		w.result = "closed"
		httpx.JSON(w, http.StatusOK, PublishResponse{OK: true, ServerID: id, Closed: true,
			Interval: int(core.Interval / time.Second), TTL: int(core.TTL / time.Second), MasterTime: now.Unix()})
		return
	}
	if allowed, wait := s.publishKey.Allow(identity.KeyID); !allowed {
		s.limited(w, wait, "too many publishes with this key")
		return
	}
	if allowed, wait := s.publishServer.Allow(id); !allowed {
		s.limited(w, wait, fmt.Sprintf("a server publishes at most once each %s", s.M.Config.PublishInterval))
		return
	}
	live, err := s.M.LiveServers(identity.Publisher.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	others := 0
	for _, other := range live {
		if other.ID == id {
			continue
		}
		if other.Instance == p.Instance {
			s.fail(w, http.StatusForbidden, "instance_taken", "instance "+p.Instance+
				" is published by another key of this publisher (server "+other.ID+")", "instance")
			return
		}
		others++
	}
	if others >= identity.Quota {
		s.fail(w, http.StatusForbidden, "quota_exceeded", fmt.Sprintf("the publisher may have %d servers at "+
			"once", identity.Quota), "")
		return
	}
	displaced, holder, err := s.hostKeyHolders(identity, l, now)
	if err != nil {
		s.internal(w, err)
		return
	}
	if holder != nil {
		s.listingTaken(identity, id, holder, l)
		s.fail(w, http.StatusForbidden, "listing_taken", "the listing's host key is live under another "+
			"publisher's server ("+holder.ID+")", "listing")
		return
	}

	observed := client.IP.Unmap()
	if p.Address != "" {
		declared, _ := netip.ParseAddrPort(p.Address)
		if netaddr.Local(declared.Addr()) && !netaddr.Local(observed) {
			s.fail(w, http.StatusBadRequest, "schema", "address is a public address", "address")
			return
		}
	}
	probeAddress := p.Address
	if probeAddress == "" {
		probeAddress = probe.Canonical(netip.AddrPortFrom(observed, uint16(p.TunnelPort)))
		if s.M.Config.Probe && (existing == nil || !existing.Trusted) && !netaddr.Global(observed) &&
			!netaddr.Local(observed) {
			s.fail(w, http.StatusBadRequest, "schema", "the master cannot probe "+observed.String()+
				", which is not a globally routable address: publish the server's address "+
				"(network.public_address)", "address")
			return
		}
	}
	// a new instance makes a record: past the publisher's quota and
	// DormantInstances, its oldest records not live are dropped first
	if existing == nil {
		limit := identity.Quota + DormantInstances
		if n, err := s.M.Store.CountServers(identity.Publisher.ID); err != nil {
			s.internal(w, err)
			return
		} else if n >= limit {
			if _, err := s.M.Store.DropDormant(identity.Publisher.ID, now.Unix()-int64(core.TTL/time.Second),
				limit-1); err != nil {
				s.internal(w, err)
				return
			}
			if n, err = s.M.Store.CountServers(identity.Publisher.ID); err != nil {
				s.internal(w, err)
				return
			} else if n >= limit {
				s.fail(w, http.StatusForbidden, "too_many_instances", fmt.Sprintf("the publisher has %d server "+
					"records, which an admin flagged or which are live: no new instance until they go", n), "instance")
				return
			}
		}
	}
	server := &model.Server{ID: id, Created: now.Unix(), Probe: string(probe.Pending)}
	wasListed := false
	if existing != nil {
		if previous, err := s.M.State(existing.PublisherID); err == nil {
			wasListed = s.M.Listable(existing, previous, now) == ""
		}
		copied := *existing
		server = &copied
	}
	warnings := contradictions(p.Declared, l)
	if existing != nil && string(existing.HostKey) == string(l.Key) && int64(l.Sequence) < existing.Sequence {
		warnings = append(warnings, "listing: older than the one the master holds (its sequence); that one is kept")
	} else {
		if existing == nil || string(existing.HostKey) != string(l.Key) || int64(l.Sequence) > existing.Sequence {
			server.ListingChanged = now.Unix()
		}
		server.Listing, server.HostKey, server.Sequence, server.ListingTime = p.Listing, l.Key, int64(l.Sequence),
			int64(l.Time)
		server.Name, server.Map, server.Gametype = l.Name, l.Map, l.Gametype
		server.Players, server.MaxPlayers, server.Engine, server.Kind = l.Players, l.MaxPlayers, l.Engine, l.Kind
		server.Teams, server.InProgress, server.Password, server.Open = l.Teams(), l.InProgress(), l.Password(), l.Open()
		server.NetworkVersion = l.NetworkVersion
		server.Dedicated = l.Dedicated() || p.Dedicated
	}
	server.PublisherID, server.KeyID, server.Instance = identity.Publisher.ID, identity.KeyID, p.Instance
	server.Variant, server.Build, server.Region, server.TunnelPort = p.Variant, p.Build, p.Region, p.TunnelPort
	server.Observed, server.Declared, server.PublishAddress = observed.String(), p.Address, p.HasAddress
	server.Serial, server.Closed, server.Updated = p.Serial, false, now.Unix()
	if server.ProbeAddress != probeAddress {
		server.ProbeAddress, server.Probe, server.Reachable, server.ProbedAt = probeAddress, string(probe.Pending),
			false, 0
	}
	switch {
	case !s.M.Config.Probe:
		server.Probe = "off"
	case server.Trusted:
		server.Probe = "skipped"
		if s.Prober != nil {
			s.Prober.Remove(id)
		}
	case s.Prober != nil:
		known := &probe.Known{Address: server.ProbeAddress, State: probe.State(server.Probe),
			ProbedAt: time.Unix(server.ProbedAt, 0)}
		state := s.Prober.Touch(id, probeAddress, identity.KeyID, identity.PublicKey, known)
		if string(state) != server.Probe {
			server.Probe = string(state)
			server.Reachable = state == probe.OK
		}
	}
	for _, old := range displaced {
		if err := s.M.Store.CloseServer(old.ID); err != nil {
			s.internal(w, err)
			return
		}
		if s.Prober != nil {
			s.Prober.Remove(old.ID)
		}
		_ = s.M.Store.Audit("publisher:"+identity.KeyID, "listing-taken-over", old.ID, fmt.Sprintf("host key "+
			"%x: server %s of publisher %s, its listing (sequence %d) not renewed for %s, closed for server %s of "+
			"publisher %s (sequence %d)", l.Key[:8], old.ID, old.PublisherID, old.Sequence,
			time.Duration(now.Unix()-old.ListingChanged)*time.Second, id, identity.Publisher.ID, l.Sequence))
		s.M.Log.Warn("a listing's host key taken over", "host_key", fmt.Sprintf("%x", l.Key[:8]), "from", old.ID,
			"to", id)
		s.invalidate()
	}
	if err := s.M.Store.PutServer(server); err != nil {
		s.internal(w, err)
		return
	}
	if existing == nil {
		_ = s.M.Store.Audit("publisher:"+identity.KeyID, "server-new", id, "instance "+p.Instance)
	}
	state, err := s.M.State(identity.Publisher.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	why := s.M.Listable(server, state, now)
	// (the list is cached for CacheTime; a server that comes or goes clears it)
	if (why == "") != wasListed {
		s.invalidate()
	}
	response := PublishResponse{
		OK: true, ServerID: id, Listed: why == "", Interval: int(core.Interval / time.Second),
		TTL: int(core.TTL / time.Second), Probe: server.Probe, Reachable: server.Probe == string(probe.OK),
		ObservedAddress: observed.String(), Warnings: warnings, MasterTime: now.Unix(),
	}
	if server.Probe == string(probe.Failed) || server.Probe == string(probe.Pending) {
		response.ProbeAddress = server.ProbeAddress
	}
	switch why {
	case "hidden":
		response.Hidden, response.Reason = true, server.HiddenReason
	case "probe":
		if server.Probe == string(probe.Failed) {
			response.Reason = fmt.Sprintf("the master's probe of %s was not answered: let UDP port %d through "+
				"your firewall or NAT, or set network.public_address", server.ProbeAddress, server.TunnelPort)
		}
	}
	status := http.StatusOK
	w.result = "ok"
	if !response.Listed && server.Probe == string(probe.Pending) {
		status = http.StatusAccepted
		w.result = "pending"
	} else if !response.Listed {
		w.result = "unlisted"
	}
	httpx.JSON(w, status, response)
}

// hostKeyHolders finds who holds a listing's host key: a host's listing is
// published by one publisher at a time, so that a listing's bytes copied
// from a list cannot be published by another. It returns the live servers
// of other publishers that this publish takes the host key from (they have
// not taken a newer listing of the host for BindingStale, and this one is
// newer), or the server that keeps it, which refuses this publish. A server
// an admin hid, or whose publisher or key is no longer approved, holds
// nothing: that is how an admin settles a dispute.
func (s *Server) hostKeyHolders(identity *core.Identity, l *listing.Listing, now time.Time) ([]model.Server,
	*model.Server, error) {
	holders, err := s.M.Store.LiveHostKey(l.Key, now.Unix()-int64(core.TTL/time.Second), identity.Publisher.ID)
	if err != nil {
		return nil, nil, err
	}
	var displaced []model.Server
	states := map[string]*core.PublisherState{}
	for i := range holders {
		holder := &holders[i]
		state, seen := states[holder.PublisherID]
		if !seen {
			if state, err = s.M.State(holder.PublisherID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, nil, err
			}
			states[holder.PublisherID] = state
		}
		switch s.M.Listable(holder, state, now) {
		case "hidden", "publisher", "key":
			continue
		}
		if now.Unix()-holder.ListingChanged >= int64(BindingStale/time.Second) && int64(l.Sequence) > holder.Sequence {
			displaced = append(displaced, *holder)
			continue
		}
		return nil, holder, nil
	}
	return displaced, nil, nil
}

// listingTaken records a publish refused for a host key another publisher
// holds, once an hour for a server and holder, for the admins (the
// servers' page shows them).
func (s *Server) listingTaken(identity *core.Identity, id string, holder *model.Server, l *listing.Listing) {
	if ok, _ := s.takenAudits.Allow(id + " " + holder.ID); !ok {
		return
	}
	_ = s.M.Store.Audit("publisher:"+identity.KeyID, "listing-taken", id, fmt.Sprintf("publisher %s refused "+
		"host key %x (sequence %d): held by server %s of publisher %s (sequence %d)", identity.Publisher.ID,
		l.Key[:8], l.Sequence, holder.ID, holder.PublisherID, holder.Sequence))
	s.M.Log.Warn("a publish refused: the listing's host key is another publisher's", "server", id,
		"holder", holder.ID)
}

func (s *Server) unpublish(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.protected(w, r); !ok {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	identity := s.authenticate(w, r, body)
	if identity == nil {
		return
	}
	if identity.KeyStatus == model.KeyRevoked {
		s.fail(w, http.StatusForbidden, "key_revoked", "key "+identity.KeyID+" is revoked", "")
		return
	}
	id := r.PathValue("id")
	server, err := s.M.Store.Server(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (identity.Publisher == nil ||
		server.PublisherID != identity.Publisher.ID)) {
		s.fail(w, http.StatusNotFound, "not_found", "no server "+id+" of this publisher", "")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.M.Store.CloseServer(id); err != nil {
		s.internal(w, err)
		return
	}
	if s.Prober != nil {
		s.Prober.Remove(id)
	}
	s.invalidate()
	s.count("closed")
	httpx.JSON(w, http.StatusOK, PublishResponse{OK: true, ServerID: id, Closed: true,
		Interval: int(core.Interval / time.Second), TTL: int(core.TTL / time.Second), MasterTime: s.M.Now().Unix()})
}
