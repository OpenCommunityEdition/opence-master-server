package api_test

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

type staticNetlist struct{ p *netlist.Published }

func (s staticNetlist) Current() *netlist.Published { return s.p }

func TestNetlistEndpoint(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false })
	status, headers, data := h.do("GET", "/v1/netlist", nil, "")
	var answer map[string]any
	_ = json.Unmarshal(data, &answer)
	if status != 503 || answer["error"].(map[string]any)["code"] != "netlist_unavailable" ||
		headers.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("%d %s", status, data)
	}

	body := netlist.Encode([]netlist.Range{{First: 0x01020300, Last: 0x010203ff}, {First: 0x05060708, Last: 0x05060708}},
		1760900000, 3)
	h.api.Netlist = staticNetlist{&netlist.Published{Body: body, Signature: sign.SignBody(h.m.Key, body), Serial: 3,
		Generated: 1760900000, Ranges: 2, Addresses: 257, ETag: netlist.ETag(body)}}
	status, headers, data = h.do("GET", "/v1/netlist", nil, "")
	if status != 200 || !bytes.Equal(data, body) {
		t.Fatalf("%d %x", status, data)
	}
	public := h.m.Key.Public().(ed25519.PublicKey)
	if !sign.VerifyBody(public, headers.Get("Signature"), data) || headers.Get("Signature-Key") != h.m.KeyID ||
		headers.Get("Signature-Time") != "1760900000" || headers.Get("Content-Type") != "application/octet-stream" ||
		headers.Get("Cache-Control") != "public, max-age=300" || headers.Get("ETag") != netlist.ETag(body) ||
		headers.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("headers %v", headers)
	}
	if _, err := netlist.Decode(data); err != nil {
		t.Fatal(err)
	}
	status, _, _ = h.doWith("GET", "/v1/netlist", nil, map[string]string{"If-None-Match": headers.Get("ETag")})
	if status != 304 {
		t.Fatalf("If-None-Match: %d", status)
	}
	request, _ := http.NewRequest("GET", h.server.URL+"/v1/netlist", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response, err := (&http.Transport{DisableCompression: true}).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader, err := gzip.NewReader(response.Body)
	if err != nil || response.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip: %v %v", err, response.Header)
	}
	unzipped, _ := io.ReadAll(reader)
	if !bytes.Equal(unzipped, body) || !sign.VerifyBody(public, response.Header.Get("Signature"), unzipped) {
		t.Fatal("the gzipped body")
	}
	if n, _ := strconv.Atoi(response.Header.Get("Content-Length")); n == len(body) {
		t.Fatal("not compressed")
	}
}

func TestNetlistLimited(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.ListPerMinute = 2 })
	statuses := []int{}
	for range 4 {
		status, _, _ := h.do("GET", "/v1/netlist", nil, "")
		statuses = append(statuses, status)
	}
	if statuses[3] != 429 {
		t.Fatalf("%v", statuses)
	}
}
