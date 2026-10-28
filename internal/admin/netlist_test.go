package admin_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
)

const bearerToken = "admin-token-for-the-tests-0123456789"

// bearer sends a request with the admin token.
func bearer(t *testing.T, method, link string, form url.Values) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, _ := http.NewRequest(method, link, body)
	request.Header.Set("Authorization", "Bearer "+bearerToken)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return read(t)(http.DefaultClient.Do(request))
}

func TestNetlistPage(t *testing.T) {
	m, pages, server := newMaster(t, func(c *config.Config) { c.Name, c.AdminToken = "Netlist master", bearerToken })
	status, page := bearer(t, "GET", server.URL+"/admin/netlist", nil)
	if status != 200 || !strings.Contains(page, "MASTER_NETLIST=off") {
		t.Fatalf("%d %s", status, page)
	}

	sources := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/list.txt":
			io.WriteString(w, "20.0.0.0/16\n")
		case "/tor.txt":
			io.WriteString(w, "30.0.0.1\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer sources.Close()
	b := netlist.New(m.Store, m.Key, http.DefaultClient, slog.New(slog.NewTextHandler(io.Discard, nil)),
		[]netlist.Source{netlist.NewSource(netlist.KindList, sources.URL+"/list.txt"),
			netlist.NewSource(netlist.KindTor, sources.URL+"/tor.txt")}, 24*time.Hour, time.Hour, "test")
	pages.Netlist = b
	if r, err := b.BuildNow(context.Background(), true); err != nil || r.Outcome != netlist.OutcomePublished {
		t.Fatalf("%+v %v", r, err)
	}
	status, page = bearer(t, "GET", server.URL+"/admin/netlist?ip=30.0.0.1", nil)
	if status != 200 || !strings.Contains(page, "tor exit") || !strings.Contains(page, "65,537") ||
		!strings.Contains(page, sources.URL+"/list.txt") {
		t.Fatalf("%d %s", status, page)
	}
	status, page = bearer(t, "POST", server.URL+"/admin/netlist/policy", url.Values{netlist.PolicyBlock: {"nonsense"}})
	if status == 200 {
		t.Fatalf("a bad setting taken: %s", page)
	}
	status, _ = bearer(t, "POST", server.URL+"/admin/netlist/policy", url.Values{netlist.PolicyBlock: {"40.0.0.0/24"},
		netlist.PolicyExtraASNs: {""}})
	if status != 200 {
		t.Fatal(status)
	}
	policy, _ := b.Policy()
	if policy[netlist.PolicyBlock] != "40.0.0.0/24" || policy[netlist.PolicyExtraASNs] != "" {
		t.Fatalf("%v", policy)
	}
	status, _ = bearer(t, "POST", server.URL+"/admin/netlist/publish", url.Values{})
	if status == 200 {
		t.Fatal("published with nothing held")
	}
	status, _ = bearer(t, "POST", server.URL+"/admin/netlist/rebuild", url.Values{})
	entries, _ := m.Store.AuditActions("netlist-rebuild", 0, 10)
	policies, _ := m.Store.AuditActions("netlist-policy", 0, 10)
	if status != 200 || len(entries) != 1 || len(policies) != 1 {
		t.Fatalf("%d %v %v", status, entries, policies)
	}
}
