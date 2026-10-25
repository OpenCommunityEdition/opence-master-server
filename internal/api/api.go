// Package api is the master's HTTP interface: the protocol's /v1 endpoints,
// /healthz and /metrics, with the public pages (package web) and the admin
// pages (package admin) mounted beside them.
package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/metrics"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// MaximumBody is the largest request body taken.
const MaximumBody = 16 << 10

// Server is the HTTP interface.
type Server struct {
	M       *core.Master
	Prober  *probe.Prober
	Metrics *metrics.Counters
	Clients *httpx.Clients

	publishAddress *limit.Limiter
	publishKey     *limit.Limiter
	publishServer  *limit.Limiter
	lists          *limit.Limiter
	takenAudits    *limit.Limiter

	cacheMu         sync.Mutex
	cache           map[string]*signedBody
	cacheGeneration uint64

	gaugesMu sync.Mutex
	gauges   *gauges
}

// New makes the interface.
func New(m *core.Master, prober *probe.Prober, counters *metrics.Counters, clients *httpx.Clients) *Server {
	now := func() time.Time { return m.Now() }
	s := &Server{
		M: m, Prober: prober, Metrics: counters, Clients: clients,
		publishAddress: limit.PerMinute(120, now).Grouped(netaddr.Group),
		publishKey:     limit.PerMinute(120, now),
		publishServer:  limit.New(2, m.Config.PublishInterval, now),
		lists:          limit.PerMinute(m.Config.ListPerMinute, now).Grouped(netaddr.Group),
		takenAudits:    limit.New(1, time.Hour, now),
		cache:          map[string]*signedBody{},
	}
	counters.Define("master_publishes_total", "Publishes, by result (ok, pending, or the error code).", "result")
	counters.Define("master_probes_total", "Probe rounds ended, by result, and probe datagrams sent.", "result")
	counters.Define("master_list_requests_total", "Requests for the list.", "")
	counters.Define("master_peer_requests_total", "Peers' requests for the shared approvals.", "")
	if prober != nil {
		prober.OnResult = s.probeResult
		prober.OnSend = func() { counters.Add("master_probes_total", "sent") }
	}
	return s
}

// ListLimiter is the limiter of the list's requests (MASTER_LIST_RATE), for
// the list page to share.
func (s *Server) ListLimiter() *limit.Limiter { return s.lists }

func (s *Server) probeResult(r probe.Result) {
	s.Metrics.Add("master_probes_total", string(r.State))
	if err := s.M.Store.SetProbe(r.ServerID, r.Address, string(r.State), r.State == probe.OK, r.At.Unix()); err != nil {
		s.M.Log.Warn("probe: not stored", "err", err)
	}
	if s.M.Config.LogAddresses {
		s.M.Log.Info("probe", "server", r.ServerID, "address", r.Address, "result", r.State, "rtt", r.RTT)
	} else {
		s.M.Log.Debug("probe", "server", r.ServerID, "result", r.State)
	}
	s.invalidate()
}

// Routes adds the protocol's endpoints to a mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/servers/{id}", s.publish)
	mux.HandleFunc("DELETE /v1/servers/{id}", s.unpublish)
	mux.HandleFunc("GET /v1/servers", s.list)
	mux.HandleFunc("GET /v1/servers/{id}", s.server)
	mux.HandleFunc("GET /v1/publishers", s.shared)
	mux.HandleFunc("GET /v1/publishers/{id}", s.publisher)
	mux.HandleFunc("/v1/applications", s.applicationsGone)
	mux.HandleFunc("/v1/applications/", s.applicationsGone)
	mux.HandleFunc("POST /v1/keys", s.addKey)
	mux.HandleFunc("GET /v1/me", s.me)
	mux.HandleFunc("GET /v1/master", s.info)
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, "not_found", "no such endpoint", "")
	})
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.metrics)
}

func (s *Server) fail(w http.ResponseWriter, status int, code, message, field string) {
	if rw, ok := w.(*resultWriter); ok {
		rw.result = code
	}
	httpx.JSON(w, status, httpx.ErrorBody{Error: httpx.ErrorDetail{Code: code, Message: message, Field: field},
		MasterTime: s.M.Now().Unix()})
}

func (s *Server) limited(w http.ResponseWriter, wait time.Duration, what string) {
	seconds := int(wait/time.Second) + 1
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	s.fail(w, http.StatusTooManyRequests, "rate_limited", what, "")
}

// readBody reads a body of MaximumBody at most; false (answered) if larger.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaximumBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.fail(w, http.StatusRequestEntityTooLarge, "too_large", "a body is 16 KB at most", "")
		} else {
			s.fail(w, http.StatusBadRequest, "schema", "the body could not be read", "")
		}
		return nil, false
	}
	return body, true
}

// requestPath is the path as the request line has it, without the query:
// what a request's signature covers.
func requestPath(r *http.Request) string {
	path := r.RequestURI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		path = r.URL.EscapedPath()
	}
	return path
}

// authenticate checks a request's OpenCE-Ed25519 signature and nonce; it
// answers the request itself and returns nil when they fail.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, body []byte) *core.Identity {
	auth, err := sign.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "bad_signature", err.Error(), "")
		return nil
	}
	now := s.M.Now()
	if !auth.InWindow(now) {
		s.fail(w, http.StatusUnauthorized, "clock", "ts is more than 300 seconds from the master's clock "+
			"(master_time)", "")
		return nil
	}
	// (unknown_key comes before the signature's check, so whether a key id
	// is known can be asked without the key: a known property, documented)
	identity, err := s.M.Identify(auth.KeyID)
	if errors.Is(err, core.ErrUnknownKey) {
		s.fail(w, http.StatusForbidden, "unknown_key", "no publisher or application has key "+auth.KeyID, "")
		return nil
	} else if err != nil {
		s.internal(w, err)
		return nil
	}
	if !auth.Verify(identity.PublicKey, s.M.KeyID, r.Method, requestPath(r), body) {
		s.fail(w, http.StatusUnauthorized, "bad_signature", "the signature does not verify", "")
		return nil
	}
	fresh, err := s.M.Store.UseNonce(auth.KeyID, auth.Nonce, sign.NonceWindow)
	if err != nil {
		s.internal(w, err)
		return nil
	}
	if !fresh {
		s.fail(w, http.StatusUnauthorized, "replay", "the nonce was used in the last 600 seconds", "")
		return nil
	}
	_ = s.M.Store.TouchKey(auth.KeyID)
	return identity
}

// approved answers 403 for a key that may not publish, and says whether it
// may.
func (s *Server) approved(w http.ResponseWriter, id *core.Identity) bool {
	code, message := "", ""
	switch {
	case id.KeyStatus == model.KeyRevoked:
		code, message = "key_revoked", "key "+id.KeyID+" is revoked"
	case id.Status == model.Pending:
		code, message = "publisher_pending", "the application for this key is waiting for review"
	case id.Status == model.ApplicationDenied:
		code, message = "application_denied", "the application for this key was denied: "+id.Reason
	case id.Status == model.Suspended:
		code, message = "publisher_suspended", "the publisher is suspended"
		if id.Reason != "" {
			message += ": " + id.Reason
		}
	case id.Status == model.Revoked:
		code, message = "publisher_revoked", "the publisher is revoked"
	case id.Status != model.Approved:
		code, message = "unknown_key", "the key is not a publisher's"
	}
	if code == "" {
		return true
	}
	s.fail(w, http.StatusForbidden, code, message, "")
	return false
}

// protected answers 403 tls_required for a request over plain HTTP from
// beyond loopback.
func (s *Server) protected(w http.ResponseWriter, r *http.Request) (httpx.Client, bool) {
	client := s.Clients.Of(r)
	if !client.Protected() {
		s.fail(w, http.StatusForbidden, "tls_required", "this request is taken over HTTPS only", "")
		return client, false
	}
	return client, true
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.M.Log.Error("internal error", "err", err)
	s.fail(w, http.StatusInternalServerError, "internal", "the master failed; try again later", "")
}

func (s *Server) actionError(w http.ResponseWriter, err error) {
	var action *core.ActionError
	var field *core.FieldError
	switch {
	case errors.As(err, &field):
		s.fail(w, http.StatusBadRequest, "schema", field.Message, field.Field)
	case errors.As(err, &action):
		status := http.StatusConflict
		switch action.Code {
		case "not_found":
			status = http.StatusNotFound
		case "too_many_keys", "revoked":
			status = http.StatusForbidden
		case "schema":
			status = http.StatusBadRequest
		}
		s.fail(w, status, action.Code, action.Message, "")
	default:
		s.internal(w, err)
	}
}

// decodeObject reads a JSON object's fields, refusing anything else.
func decodeObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, errors.New("the body is a JSON object")
	}
	if decoder.More() {
		return nil, errors.New("the body is one JSON object")
	}
	return fields, nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.M.Store.Ping(); err != nil {
		s.fail(w, http.StatusServiceUnavailable, "internal", "the database does not answer", "")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "name": s.M.Name(), "time": s.M.Now().Unix(),
		"protocol": core.Protocol})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "protocol": core.Protocol, "version": core.Version,
		"master": map[string]any{"name": s.M.Name(), "key_id": s.M.KeyID, "time": s.M.Now().Unix(),
			"public_key": sign.PublicKeyText(s.M.Key.Public().(ed25519.PublicKey))},
		"contact": s.M.Contact(), "data_policy": s.M.Config.DataPolicy, "probe": s.M.Config.Probe,
		"interval": int(core.Interval / time.Second), "ttl": int(core.TTL / time.Second),
		"default_quota": s.M.Config.DefaultQuota,
	})
}
