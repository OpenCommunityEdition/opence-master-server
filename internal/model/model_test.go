package model

import "testing"

func TestEffectiveMostRestrictiveWins(t *testing.T) {
	all := func(string) bool { return true }
	opinions := []Opinion{
		{Source: "a", Status: Approved, Quota: 4, Updated: 100},
		{Source: "b", Status: Suspended, Quota: 0, Updated: 50},
	}
	status, quota, by := Effective(opinions, all)
	if status != Suspended || by != "b" || quota != 4 {
		t.Fatalf("%s %d %s", status, quota, by)
	}
	opinions = append(opinions, Opinion{Source: "c", Status: Revoked, Quota: 2, Updated: 10})
	if status, quota, _ = Effective(opinions, all); status != Revoked || quota != 2 {
		t.Fatalf("%s %d", status, quota)
	}
	// an untrusted source's word does not count
	if status, _, _ = Effective(opinions, func(s string) bool { return s == "a" }); status != Approved {
		t.Fatal(status)
	}
	if status, _, _ = Effective(opinions, func(string) bool { return false }); status != "" {
		t.Fatal("no trusted source, yet a status")
	}
}

func TestResumeOnlyLiftsOwnSuspension(t *testing.T) {
	all := func(string) bool { return true }
	// a suspends; b's record stays approved: suspended
	opinions := []Opinion{{Source: "a", Status: Suspended, Updated: 200}, {Source: "b", Status: Approved, Updated: 300}}
	if s, _, _ := Effective(opinions, all); s != Suspended {
		t.Fatal(s)
	}
	// a resumes (its newer word replaces its own): approved
	opinions[0] = Opinion{Source: "a", Status: Approved, Updated: 400}
	if s, _, _ := Effective(opinions, all); s != Approved {
		t.Fatal(s)
	}
}

func TestNewer(t *testing.T) {
	if !Newer(2, 1, Approved, Suspended) || Newer(1, 2, Revoked, Approved) {
		t.Fatal("time does not decide")
	}
	if !Newer(5, 5, Suspended, Approved) || Newer(5, 5, Approved, Suspended) || Newer(5, 5, Approved, Approved) {
		t.Fatal("a tie is not the more restrictive")
	}
	if !Newer(5, 5, KeyRevoked, KeyActive) {
		t.Fatal("a tie is not the revoked key")
	}
}

func TestEffectiveKey(t *testing.T) {
	all := func(string) bool { return true }
	records := []KeyRecord{{Source: "a", PublisherID: "p_1", PublicKey: "k", Status: KeyActive}}
	if p, _, s := EffectiveKey(records, all); p != "p_1" || s != KeyActive {
		t.Fatal(p, s)
	}
	records = append(records, KeyRecord{Source: "b", PublisherID: "p_1", PublicKey: "k", Status: KeyRevoked})
	if _, _, s := EffectiveKey(records, all); s != KeyRevoked {
		t.Fatal("a revocation anywhere does not win")
	}
	if _, _, s := EffectiveKey(records, func(x string) bool { return x == "a" }); s != KeyActive {
		t.Fatal("an untrusted revocation counted")
	}
	conflict := []KeyRecord{{Source: "a", PublisherID: "p_1", PublicKey: "k", Status: KeyActive},
		{Source: "b", PublisherID: "p_2", PublicKey: "k", Status: KeyActive}}
	if p, _, _ := EffectiveKey(conflict, all); p != "" {
		t.Fatal("a key claimed by two publishers is used")
	}
}
