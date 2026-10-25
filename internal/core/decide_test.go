package core_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// newMaster makes a master on a database file (several connections, as
// served), with limits that the tests set.
func newMaster(t *testing.T, change func(*config.Config)) *core.Master {
	t.Helper()
	values := config.Flags(flag.NewFlagSet("test", flag.ContinueOnError))
	for _, o := range config.Options {
		*values[o.Env] = o.Default
	}
	cfg, err := config.Load(values)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name, cfg.Contact = "Test master", "ops@example.org"
	cfg.ApplicationsPerHour, cfg.ApplicationsPerKey, cfg.ApplicationsPerDay = 100000, 100000, 100000
	if change != nil {
		change(cfg)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "master.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := sign.NewSeed()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := core.New(st, key, cfg, &mail.Notifier{Log: log, Client: http.DefaultClient, Sync: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func input(m *core.Master, key ed25519.PrivateKey, discordID string) core.ApplicationInput {
	nonce := m.ProofNonce(discordID)
	in := core.ApplicationInput{Name: "Operator", Servers: 1,
		PublicKey: sign.PublicKeyText(key.Public().(ed25519.PublicKey)),
		Proof:     &core.Proof{Nonce: nonce, Signature: hex.EncodeToString(ed25519.Sign(key, []byte(nonce)))}}
	if discordID != "" {
		in.DiscordID, in.DiscordName = discordID, "op"
	}
	return in
}

func code(err error) string {
	var action *core.ActionError
	if errors.As(err, &action) {
		return action.Code
	}
	return ""
}

// at runs fs at once, each on its own goroutine, and returns their errors.
func at(fs ...func() error) []error {
	errs := make([]error, len(fs))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, f := range fs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// Two approvals and a denial of one application at once (two approvers, or
// Discord and the admin page): one is made, the others refused, and the
// records agree with it: a denied application has no publisher or key, an
// approved one one publisher and one key.
func TestDecisionsAtOnce(t *testing.T) {
	m := newMaster(t, nil)
	publishers := 0
	for try := 0; try < 200; try++ {
		key, _ := sign.NewSeed()
		a, err := m.Apply(input(m, key, ""), "test")
		if err != nil {
			t.Fatal(err)
		}
		approve := func() error { _, err := m.Approve(a.ID, 0, "approver"); return err }
		errs := at(approve, func() error { return m.Deny(a.ID, "no", "denier") }, approve)
		made := 0
		for _, err := range errs {
			if err == nil {
				made++
			} else if c := code(err); c != "not_pending" && c != "already_approved" {
				t.Fatalf("try %d: a refusal %v", try, err)
			}
		}
		if made != 1 {
			t.Fatalf("try %d: %d decisions made (%v)", try, made, errs)
		}
		got, err := m.Store.Application(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		records, _ := m.Store.KeyRecords(a.KeyID)
		all, _ := m.Store.Publishers()
		switch {
		case errs[1] == nil && (got.Status != model.ApplicationDenied || got.PublisherID != "" || len(records) != 0 ||
			len(all) != publishers):
			t.Fatalf("try %d: denied, with %+v, %d keys, %d publishers", try, got, len(records), len(all))
		case errs[1] != nil && (got.Status != model.ApplicationApproved || len(records) != 1 ||
			records[0].PublisherID != got.PublisherID || records[0].Status != model.KeyActive ||
			len(all) != publishers+1):
			t.Fatalf("try %d: approved, with %+v, keys %+v, %d publishers", try, got, records, len(all))
		}
		publishers = len(all)
	}
}

// Two applications for one key (one taken by hand) approved at once: one
// publisher has the key.
func TestApprovalsOfOneKeyAtOnce(t *testing.T) {
	m := newMaster(t, nil)
	for try := 0; try < 50; try++ {
		key, _ := sign.NewSeed()
		a, err := m.Apply(input(m, key, ""), "test")
		if err != nil {
			t.Fatal(err)
		}
		b := *a
		b.ID = fmt.Sprintf("a_copy%d", try)
		if err := m.Store.CreateApplication(&b); err != nil {
			t.Fatal(err)
		}
		errs := at(func() error { _, err := m.Approve(a.ID, 0, "x"); return err },
			func() error { _, err := m.Approve(b.ID, 0, "y"); return err })
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("try %d: %v", try, errs)
		}
		refused, loser := errs[0], a.ID
		if refused == nil {
			refused, loser = errs[1], b.ID
		}
		if code(refused) != "key_exists" {
			t.Fatalf("try %d: %v", try, refused)
		}
		if records, _ := m.Store.KeyRecords(a.KeyID); len(records) != 1 {
			t.Fatalf("try %d: %d key records", try, len(records))
		}
		if got, _ := m.Store.Application(loser); got.Status != model.ApplicationPending || got.PublisherID != "" {
			t.Fatalf("try %d: the refused approval left %+v", try, got)
		}
	}
	if all, _ := m.Store.Publishers(); len(all) != 50 {
		t.Fatalf("%d publishers", len(all))
	}
}

// A denied application is not approved after all (a stale Approve button,
// or the command line), nor denied again.
func TestDeniedStaysDenied(t *testing.T) {
	m := newMaster(t, nil)
	key, _ := sign.NewSeed()
	a, err := m.Apply(input(m, key, ""), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Deny(a.ID, "not now", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Approve(a.ID, 0, "cli"); code(err) != "not_pending" || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("a denied application approved: %v", err)
	}
	if err := m.Deny(a.ID, "again", "admin"); code(err) != "not_pending" {
		t.Fatalf("denied twice: %v", err)
	}
	got, _ := m.Store.Application(a.ID)
	records, _ := m.Store.KeyRecords(a.KeyID)
	all, _ := m.Store.Publishers()
	if got.Status != model.ApplicationDenied || got.Reason != "not now" || got.DecidedBy != "admin" ||
		len(records) != 0 || len(all) != 0 {
		t.Fatalf("%+v, %d keys, %d publishers", got, len(records), len(all))
	}
	// an approved one is not approved again
	b, err := m.Apply(input(m, key, ""), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Approve(b.ID, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Approve(b.ID, 0, "admin"); code(err) != "already_approved" {
		t.Fatalf("approved twice: %v", err)
	}
}

// Eight applications sent at once by one Discord user: one is taken, the
// others refused as duplicates; and eight for one key from eight users.
func TestApplicationsAtOnce(t *testing.T) {
	m := newMaster(t, func(c *config.Config) { c.ApplicationsPerDay = 2 })
	var fs []func() error
	for i := 0; i < 8; i++ {
		key, _ := sign.NewSeed()
		in := input(m, key, "100000000000000001")
		fs = append(fs, func() error { _, err := m.Apply(in, "test"); return err })
	}
	check := func(what string, errs []error) {
		taken := 0
		for _, err := range errs {
			if err == nil {
				taken++
			} else if code(err) != "duplicate" {
				t.Fatalf("%s: %v", what, err)
			}
		}
		if taken != 1 {
			t.Fatalf("%s: %d applications taken (%v)", what, taken, errs)
		}
	}
	check("one user", at(fs...))
	if n, _ := m.Store.ApplicationsOfDiscord("100000000000000001", 0); n != 1 {
		t.Fatalf("%d applications stored", n)
	}
	// MASTER_APPLICATIONS_PER_DAY (2) holds at once too
	pending, _ := m.Store.PendingApplicationOfDiscord("100000000000000001")
	if err := m.Deny(pending.ID, "test", "test"); err != nil {
		t.Fatal(err)
	}
	fs = nil
	for i := 0; i < 8; i++ {
		key, _ := sign.NewSeed()
		in := input(m, key, "100000000000000001")
		fs = append(fs, func() error { _, err := m.Apply(in, "test"); return err })
	}
	check("one user, the day's second", at(fs...))
	if n, _ := m.Store.ApplicationsOfDiscord("100000000000000001", 0); n != 2 {
		t.Fatalf("%d applications stored", n)
	}
	fs = nil
	key, _ := sign.NewSeed()
	for i := 0; i < 8; i++ {
		in := input(m, key, fmt.Sprintf("20000000000000000%d", i))
		fs = append(fs, func() error { _, err := m.Apply(in, "test"); return err })
	}
	check("one key", at(fs...))
}

// A denial's reason is 300 characters at most (the applicant's direct
// message fits Discord's 2000), whichever way it comes.
func TestDenialReasonLimit(t *testing.T) {
	m := newMaster(t, nil)
	key, _ := sign.NewSeed()
	a, err := m.Apply(input(m, key, ""), "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"", "   ", strings.Repeat("x", 301), strings.Repeat("é", 301)} {
		if err := m.Deny(a.ID, reason, "cli"); code(err) != "schema" {
			t.Fatalf("a reason of %d bytes: %v", len(reason), err)
		}
	}
	if got, _ := m.Store.Application(a.ID); got.Status != model.ApplicationPending {
		t.Fatalf("%+v", got)
	}
	if err := m.Deny(a.ID, strings.Repeat("é", 300), "cli"); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Store.Application(a.ID); got.Status != model.ApplicationDenied || len(got.Reason) != 600 {
		t.Fatalf("%+v", got)
	}
}
