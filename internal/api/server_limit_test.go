package api_test

import (
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
)

func TestMasterServerLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Probe = false; c.MaxServers = 1 })
	p := h.approved(10)
	q := h.approved(10)
	body := func(instance string) []byte { return publishBody(instance, h.listing(1, 0), 2302, nil) }
	if status, out := h.publish(p.key, "one", body("one")); status != 200 {
		t.Fatalf("first: %d %v", status, out)
	}
	// Same publisher cannot use their larger individual quota to bypass the cap.
	if status, out := h.publish(p.key, "two", body("two")); status != 403 || code(out) != "master_capacity" {
		t.Fatalf("second: %d %v", status, out)
	}
	// Another publisher cannot bypass the global cap either.
	otherHost, _ := sign.NewSeed()
	otherListing := listing.Make(otherHost, listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen, Sequence: 1, Time: uint32(h.clock.Now().Unix()), Players: 1, MaxPlayers: 16, Engine: 1, Name: "Other server", Map: "bloodgulch", Gametype: "CTF"})
	if status, out := h.publish(q.key, "three", publishBody("three", otherListing, 2303, nil)); status != 403 || code(out) != "master_capacity" {
		t.Fatalf("other publisher: %d %v", status, out)
	}
	if status, out := h.publish(p.key, "one", body("one")); status != 200 {
		t.Fatalf("renewal: %d %v", status, out)
	}
	live, err := h.m.Store.LiveServers("", h.clock.Now().Unix()-int64(core.TTL/time.Second))
	if err != nil || len(live) != 1 {
		t.Fatalf("live=%v err=%v", live, err)
	}
	h.clock.Add(core.TTL + time.Second)
	if status, out := h.publish(p.key, "two", body("two")); status != 200 {
		t.Fatalf("expiry: %d %v", status, out)
	}
}
