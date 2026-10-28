package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
)

// Netlists is where the netlist served comes from (the builder).
type Netlists interface {
	// the list served; nil while none is built
	Current() *netlist.Published
}

// netlist answers GET /v1/netlist: the signed netlist, its ETag (and 304
// for a match), gzip when asked (the signature is the uncompressed
// bytes'), or 503 netlist_unavailable while there is none.
func (s *Server) netlist(w http.ResponseWriter, r *http.Request) {
	if s.listLimited(w, r) {
		return
	}
	var p *netlist.Published
	if s.Netlist != nil {
		p = s.Netlist.Current()
	}
	if p == nil {
		message := "this master has built no netlist yet; try again later"
		if !s.M.Config.Netlist {
			message = "this master serves no netlist (MASTER_NETLIST=off)"
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Retry-After", "300")
		s.fail(w, http.StatusServiceUnavailable, "netlist_unavailable", message, "")
		return
	}
	h := w.Header()
	h.Set("Signature", p.Signature)
	h.Set("Signature-Key", s.M.KeyID)
	h.Set("Signature-Time", strconv.FormatInt(p.Generated, 10))
	h.Set("ETag", p.ETag)
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "Signature, Signature-Key, Signature-Time, ETag")
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "public, max-age=300")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, p.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := p.Body
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = p.Gzipped()
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
