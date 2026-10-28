package admin_test

import (
	"crypto/ed25519"
	"net/url"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func TestLinksPage(t *testing.T) {
	m, _, server := newMaster(t, func(c *config.Config) { c.Name, c.AdminToken = "Links master", bearerToken })
	player, _ := sign.NewSeed()
	public := player.Public().(ed25519.PublicKey)
	if err := m.SaveLink(public, "80351110224678912", "nelly", 1, "cli"); err != nil {
		t.Fatal(err)
	}
	keyID := sign.KeyID(public)
	for _, q := range []string{"", "nel", "80351110224678912", keyID} {
		status, page := bearer(t, "GET", server.URL+"/admin/links?q="+url.QueryEscape(q), nil)
		if status != 200 || !strings.Contains(page, keyID) || !strings.Contains(page, "nelly") {
			t.Fatalf("%q: %d %s", q, status, page)
		}
	}
	if _, page := bearer(t, "GET", server.URL+"/admin/links?q=nobody", nil); strings.Contains(page, keyID) {
		t.Fatal("a search found what it should not")
	}
	key := strings.TrimPrefix(sign.PublicKeyText(public), sign.PublicKeyPrefix)
	if status, _ := bearer(t, "POST", server.URL+"/admin/links/unlink", url.Values{"key": {key}}); status != 200 {
		t.Fatal(status)
	}
	if links, _ := m.Store.SearchLinks("", 10); len(links) != 0 {
		t.Fatalf("%+v", links)
	}
	if status, _ := bearer(t, "POST", server.URL+"/admin/links/revoke", url.Values{"discord_id": {"80351110224678912"}}); status == 200 {
		t.Fatal("a revocation without a reason taken")
	}
	if status, _ := bearer(t, "POST", server.URL+"/admin/links/revoke", url.Values{"discord_id": {"80351110224678912"},
		"reason": {"ban evasion"}}); status != 200 {
		t.Fatal(status)
	}
	if _, page := bearer(t, "GET", server.URL+"/admin/links", nil); !strings.Contains(page, "ban evasion") {
		t.Fatal("the revocation is not listed")
	}
	if status, _ := bearer(t, "POST", server.URL+"/admin/links/lift", url.Values{"discord_id": {"80351110224678912"}}); status != 200 {
		t.Fatal(status)
	}
	if r, _ := m.Revoked("80351110224678912"); r != nil {
		t.Fatal("not lifted")
	}
	for _, action := range []string{"unlink", "revoke-link", "lift-revocation"} {
		entries, _ := m.Store.AuditActions(action, 0, 10)
		if len(entries) != 1 || entries[0].Actor != "admin" {
			t.Errorf("%s: %+v", action, entries)
		}
	}
}
