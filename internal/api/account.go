package api

import (
	"encoding/json"
	"net/http"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// applicationsGone answers the earlier application endpoints (the form's
// POST, its challenge and its status): applications are made with the
// master's Discord bot.
func (s *Server) applicationsGone(w http.ResponseWriter, r *http.Request) {
	s.fail(w, http.StatusGone, "applications_by_discord", "this master takes applications through its Discord "+
		"bot (/apply), not this endpoint; see "+s.M.Link("/apply"), "")
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.protected(w, r); !ok {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	identity := s.authenticate(w, r, body)
	if identity == nil || !s.approved(w, identity) {
		return
	}
	fields, err := decodeObject(body)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "schema", err.Error(), "")
		return
	}
	var text string
	if raw, ok := fields["public_key"]; !ok || json.Unmarshal(raw, &text) != nil {
		s.fail(w, http.StatusBadRequest, "schema", "public_key is \"ed25519:<64 hex>\"", "public_key")
		return
	}
	public, err := sign.ParsePublicKey(text)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "schema", err.Error(), "public_key")
		return
	}
	keyID, err := s.M.AddKey(identity.Publisher.ID, public, "publisher:"+identity.KeyID)
	if err != nil {
		s.actionError(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"ok": true, "key_id": keyID, "status": model.KeyActive,
		"master_time": s.M.Now().Unix()})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.protected(w, r); !ok {
		return
	}
	identity := s.authenticate(w, r, nil)
	if identity == nil {
		return
	}
	if identity.KeyStatus == model.KeyRevoked {
		s.fail(w, http.StatusForbidden, "key_revoked", "key "+identity.KeyID+" is revoked", "")
		return
	}
	now := s.M.Now()
	if identity.Publisher == nil {
		a := identity.Application
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "key_id": identity.KeyID, "status": identity.Status,
			"publisher": nil, "application": map[string]any{"id": a.ID, "status": a.Status, "reason": a.Reason,
				"created": a.Created}, "master_time": now.Unix()})
		return
	}
	state, err := s.M.State(identity.Publisher.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	keys := []map[string]any{}
	for _, k := range state.Keys {
		keys = append(keys, map[string]any{"key_id": k.KeyID, "public_key": k.PublicKey, "status": k.Status,
			"updated": k.Updated, "last_used": k.LastUsed})
	}
	servers := []map[string]any{}
	all, err := s.M.LiveServers(identity.Publisher.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	for i := range all {
		v := &all[i]
		why := s.M.Listable(v, state, now)
		entry := map[string]any{"id": v.ID, "instance": v.Instance, "key_id": v.KeyID, "listed": why == "",
			"probe": v.Probe, "reachable": v.Probe == string(probe.OK), "hidden": v.Hidden, "trusted": v.Trusted,
			"updated": v.Updated, "name": v.Name, "players": v.Players, "max_players": v.MaxPlayers}
		if v.Hidden {
			entry["hidden_reason"] = v.HiddenReason
		}
		servers = append(servers, entry)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "key_id": identity.KeyID, "status": state.Status, "master_time": now.Unix(),
		"publisher": map[string]any{"id": state.Publisher.ID, "name": state.Publisher.Name,
			"since": core.Since(state.Publisher.Since), "status": state.Status, "quota": state.Quota,
			"origin": state.Publisher.Origin, "keys": keys, "servers": servers},
	})
}
