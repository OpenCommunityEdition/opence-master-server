package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// PassesPerMinute is how many passes a player key is given a minute.
const PassesPerMinute = 30

// pass answers GET /v1/pass?key&ts&sig: a new pass for a linked player
// key, signed in the query (no Authorization header, so that a client that
// can send none may ask).
func (s *Server) pass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s.listLimited(w, r) {
		return
	}
	q := r.URL.Query()
	query, err := sign.ParsePlayerQuery(q.Get("key"), q.Get("ts"), q.Get("sig"))
	if err == nil {
		err = query.Check(sign.PassGetLabel, s.M.KeyID, s.M.Now(), sign.ClockWindow)
	}
	switch {
	case errors.Is(err, sign.ErrClock):
		s.fail(w, http.StatusUnauthorized, "clock", "ts is more than 300 seconds from the master's clock "+
			"(master_time)", "")
		return
	case errors.Is(err, sign.ErrSmallOrder):
		s.fail(w, http.StatusUnauthorized, "bad_signature", "the key has a small order", "")
		return
	case err != nil:
		s.fail(w, http.StatusUnauthorized, "bad_signature", "key (64 hex), ts and sig (128 hex) are needed, and "+
			"sig must verify", "")
		return
	}
	if allowed, wait := s.passKey.Allow(query.KeyHex); !allowed {
		s.limited(w, wait, "too many passes asked for this key")
		return
	}
	pass, err := s.M.Pass(query.Key)
	var revoked *core.RevokedError
	switch {
	case errors.Is(err, core.ErrNotLinked):
		s.fail(w, http.StatusNotFound, "not_linked", "no Discord account holds this key (yet): link it at "+
			s.M.Link("/link"), "")
		return
	case errors.As(err, &revoked):
		s.fail(w, http.StatusForbidden, "link_revoked", revoked.Reason, "")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(pass)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pass)
}
