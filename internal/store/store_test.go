package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

func TestNonceWindow(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Unix(1760900000, 0)
	s.Now = func() time.Time { return now }
	window := 600 * time.Second
	if fresh, err := s.UseNonce("k", "n", window); err != nil || !fresh {
		t.Fatalf("first use: %v %v", fresh, err)
	}
	now = now.Add(599 * time.Second)
	if fresh, _ := s.UseNonce("k", "n", window); fresh {
		t.Fatal("a nonce used again within the window")
	}
	if fresh, _ := s.UseNonce("other", "n", window); !fresh {
		t.Fatal("nonces are not per key")
	}
	// (the refused use did not restart the window)
	now = now.Add(2 * time.Second)
	if fresh, _ := s.UseNonce("k", "n", window); !fresh {
		t.Fatal("a nonce past the window refused")
	}
	if err := s.Purge(window, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestMergeKeepsNewerAndRevoked(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	o := model.Opinion{PublisherID: "p_1", Source: "a", Status: model.Approved, Quota: 4, Updated: 100}
	if changed, _ := s.MergeOpinion(o); !changed {
		t.Fatal("first opinion not stored")
	}
	o.Status, o.Updated = model.Suspended, 50
	if changed, _ := s.MergeOpinion(o); changed {
		t.Fatal("an older opinion replaced a newer one")
	}
	k := model.KeyRecord{KeyID: "0123456789abcdef", Source: "a", PublisherID: "p_1", PublicKey: "ed25519:x",
		Status: model.KeyRevoked, Updated: 100}
	if changed, _ := s.MergeKey(k); !changed {
		t.Fatal("key not stored")
	}
	k.Status, k.Updated = model.KeyActive, 200
	if changed, _ := s.MergeKey(k); changed {
		t.Fatal("a revoked key was made active again")
	}
}

func TestFileModeAndMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.db")
	// a database of the first schema, without applications.address_key
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE applications (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
		discord TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL, key_id TEXT NOT NULL, servers INTEGER NOT NULL,
		region TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', proof_ok INTEGER NOT NULL DEFAULT 0,
		token_hash TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0, address TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', publisher_id TEXT NOT NULL DEFAULT '',
		created INTEGER NOT NULL, updated INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	// and of servers without listing_changed
	if _, err := old.Exec(`CREATE TABLE servers (
		id TEXT PRIMARY KEY, publisher_id TEXT NOT NULL, key_id TEXT NOT NULL, instance TEXT NOT NULL,
		name TEXT NOT NULL, map TEXT NOT NULL, gametype TEXT NOT NULL, variant TEXT NOT NULL, players INTEGER NOT NULL,
		max_players INTEGER NOT NULL, teams INTEGER NOT NULL, in_progress INTEGER NOT NULL, password INTEGER NOT NULL,
		open INTEGER NOT NULL, dedicated INTEGER NOT NULL, kind INTEGER NOT NULL, engine INTEGER NOT NULL,
		network_version INTEGER NOT NULL, build TEXT NOT NULL, region TEXT NOT NULL, tunnel_port INTEGER NOT NULL,
		listing BLOB, host_key BLOB, sequence INTEGER NOT NULL, listing_time INTEGER NOT NULL,
		observed TEXT NOT NULL, declared TEXT NOT NULL, publish_address INTEGER NOT NULL, probe_address TEXT NOT NULL,
		probe TEXT NOT NULL, reachable INTEGER NOT NULL, probed_at INTEGER NOT NULL, hidden INTEGER NOT NULL,
		hidden_reason TEXT NOT NULL, trusted INTEGER NOT NULL, closed INTEGER NOT NULL, serial INTEGER NOT NULL,
		created INTEGER NOT NULL, updated INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApplication(&model.Application{ID: "a_1", Name: "n", Email: "e@example.org", KeyID: "k",
		Status: model.ApplicationPending, AddressKey: "2001:db8::/64"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutServer(&model.Server{ID: "s", PublisherID: "p_1", ListingChanged: 42}); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Server("s"); err != nil || v.ListingChanged != 42 {
		t.Fatalf("%v %+v", err, v)
	}
	s.Close()
	// a new file is its owner's only
	fresh := filepath.Join(t.TempDir(), "new.db")
	s, err = Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	info, err := os.Stat(fresh)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %v (%v)", info.Mode(), err)
	}
}

func TestPurgeAndDormant(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	now := time.Unix(1760900000, 0)
	s.Now = func() time.Time { return now }
	put := func(id string, updated int64, closed, hidden bool) {
		if err := s.PutServer(&model.Server{ID: id, PublisherID: "p_1", Updated: updated, Closed: closed,
			Hidden: hidden, Observed: "203.0.113.5"}); err != nil {
			t.Fatal(err)
		}
	}
	at := now.Unix()
	put("live", at, false, false)
	put("closed-now", at-60, true, false)
	put("closed-old", at-2*3600, true, false)
	put("expired", at-25*3600, false, false)
	put("hidden-old", at-25*3600, false, true)
	for i, a := range []model.Application{
		{ID: "a_unverified", Status: model.ApplicationPending, Created: at - 8*86400},
		{ID: "a_verified", Status: model.ApplicationPending, EmailVerified: true, Created: at - 8*86400},
		{ID: "a_denied", Status: model.ApplicationDenied, Created: at - 40*86400, Updated: at - 31*86400},
		{ID: "a_denied_now", Status: model.ApplicationDenied, Created: at - 40*86400, Updated: at - 86400},
	} {
		a.Name, a.Email, a.KeyID = "n", "e@example.org", fmt.Sprint(i)
		if err := s.CreateApplication(&a); err != nil {
			t.Fatal(err)
		}
	}
	// a Discord applicant's (no e-mail address to verify) is kept pending
	if err := s.CreateApplication(&model.Application{ID: "a_discord", Name: "n", KeyID: "d", DiscordID: "1",
		Status: model.ApplicationPending, Created: at - 8*86400}); err != nil {
		t.Fatal(err)
	}
	s.AuditKeep = 3
	for i := 0; i < 10; i++ {
		_ = s.Audit("test", "a", "", "")
	}
	if err := s.Purge(600*time.Second, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	servers, _ := s.Servers(0)
	var ids []string
	for _, v := range servers {
		ids = append(ids, v.ID)
	}
	if fmt.Sprint(ids) != "[live closed-now hidden-old]" {
		t.Fatalf("servers kept: %v", ids)
	}
	for id, kept := range map[string]bool{"a_unverified": false, "a_verified": true, "a_denied": false,
		"a_denied_now": true, "a_discord": true} {
		if _, err := s.Application(id); (err == nil) != kept {
			t.Errorf("%s: %v", id, err)
		}
	}
	if entries, _ := s.AuditLog(100, 0); len(entries) != 3 {
		t.Fatalf("%d audit entries kept", len(entries))
	}
	// the dormant records go first, the oldest first, the flagged ones never
	for i := 0; i < 5; i++ {
		put(fmt.Sprint("dormant", i), at-int64(1000-i), false, false)
	}
	n, err := s.DropDormant("p_1", at-90, 5)
	if err != nil || n != 3 {
		t.Fatalf("dropped %d (%v)", n, err)
	}
	if _, err := s.Server("dormant0"); err == nil {
		t.Fatal("the oldest dormant record kept")
	}
	if _, err := s.Server("hidden-old"); err != nil {
		t.Fatal("a flagged record dropped")
	}
	if _, err := s.Server("live"); err != nil {
		t.Fatal("a live record dropped")
	}
}

// A publisher new here is recorded as come from the file's master, whatever
// origin another master's file claims; this master's own file keeps them.
func TestImportOrigin(t *testing.T) {
	const self, peer, third = "1111111111111111", "2222222222222222", "3333333333333333"
	export := func(master string) *Export {
		return &Export{Format: ExportFormat, Master: master, Publishers: []ExportedPublisher{{
			Publisher: model.Publisher{ID: "p_" + master[:4], Name: "Claimed", Origin: third, Since: 1, Created: 1,
				Updated: 1}}}}
	}
	s, _ := Open(":memory:")
	defer s.Close()
	for master, want := range map[string]string{peer: peer, self: third} {
		if counts, err := s.Import(export(master), self); err != nil || counts.Publishers != 1 {
			t.Fatalf("%v %+v", err, counts)
		}
		if p, err := s.Publisher("p_" + master[:4]); err != nil || p.Origin != want {
			t.Fatalf("an import of %s's file: origin %+v (%v), want %s", master, p, err, want)
		}
	}
}

func TestSettingsAndSync(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	if v, set, err := s.Setting("discord.token"); err != nil || set || v != "" {
		t.Fatalf("%q %v %v", v, set, err)
	}
	if err := s.SetSetting("discord.token", "x"); err != nil {
		t.Fatal(err)
	}
	if v, set, _ := s.Setting("discord.token"); !set || v != "x" {
		t.Fatalf("%q %v", v, set)
	}
	if err := s.SetSetting("discord.token", ""); err != nil {
		t.Fatal(err)
	}
	if _, set, _ := s.Setting("discord.token"); set {
		t.Fatal("an empty value kept")
	}
	// queued, then posted, then decided: the bot's work list follows
	a := &model.Application{ID: "a_1", Name: "n", KeyID: "k", DiscordID: "7", Status: model.ApplicationPending,
		LogQueued: true, ToldStatus: model.ApplicationPending}
	if err := s.CreateApplication(a); err != nil {
		t.Fatal(err)
	}
	work := func() int {
		list, err := s.ApplicationsToSync(10)
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if work() != 1 {
		t.Fatal("a queued application is not to sync")
	}
	_ = s.SetApplicationPosted("a_1", "c", "m", model.ApplicationPending)
	if work() != 0 {
		t.Fatal("a posted pending application is still to sync")
	}
	_ = s.SetApplicationStatus("a_1", model.ApplicationDenied, "no", "", "admin")
	if work() != 1 {
		t.Fatal("a decided application is not to sync")
	}
	got, _ := s.Application("a_1")
	if got.DecidedBy != "admin" || got.LogMessage != "m" || got.LogChannel != "c" || got.LogQueued {
		t.Fatalf("%+v", got)
	}
	_ = s.SetApplicationShown("a_1", model.ApplicationDenied)
	_ = s.SetApplicationTold("a_1", model.ApplicationDenied)
	if work() != 0 {
		t.Fatal("a synchronised application is still to sync")
	}
}
