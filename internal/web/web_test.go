package web

import (
	"net/http/httptest"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
)

// A browser's form post: its own Origin, none, or "null" from a page whose
// referrer policy hides it, which only the browser's Sec-Fetch-Site vouches
// for.
func TestSameOrigin(t *testing.T) {
	clients := &httpx.Clients{}
	cases := []struct {
		origin, fetchSite string
		want              bool
	}{
		{"http://master.test", "", true},
		{"http://MASTER.test", "same-origin", true},
		{"", "", true},
		{"http://evil.test", "", false},
		{"http://evil.test", "same-origin", false},
		{"null", "same-origin", true},
		{"null", "cross-site", false},
		{"null", "same-site", false},
		{"null", "", false},
		{"::not a url", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "http://master.test/admin/login", nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", c.fetchSite)
		}
		if got := SameOrigin(r, clients); got != c.want {
			t.Errorf("Origin %q, Sec-Fetch-Site %q: SameOrigin %v, want %v", c.origin, c.fetchSite, got, c.want)
		}
	}
}
