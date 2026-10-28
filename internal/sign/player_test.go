package sign

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestPlayerQuery(t *testing.T) {
	player := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	query, _ := url.ParseQuery(SignPlayerQuery(player, LinkLabel, "39f713d0a644253f", 1760900100))
	q, err := ParsePlayerQuery(query.Get("key"), query.Get("ts"), query.Get("sig"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1760900100, 0)
	if err := q.Check(LinkLabel, "39f713d0a644253f", at.Add(600*time.Second), LinkWindow); err != nil {
		t.Fatal(err)
	}
	if err := q.Check(LinkLabel, "39f713d0a644253f", at.Add(601*time.Second), LinkWindow); !errors.Is(err, ErrClock) {
		t.Fatalf("a stale ts: %v", err)
	}
	if err := q.Check(PassGetLabel, "39f713d0a644253f", at, ClockWindow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another label: %v", err)
	}
	if err := q.Check(LinkLabel, "0123456789abcdef", at, LinkWindow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another master: %v", err)
	}
	for _, bad := range [][3]string{
		{query.Get("key")[:63], query.Get("ts"), query.Get("sig")},
		{query.Get("key"), "01760900100", query.Get("sig")},
		{query.Get("key"), query.Get("ts"), query.Get("sig")[:127]},
		{"ED" + query.Get("key")[2:], query.Get("ts"), query.Get("sig")},
	} {
		if _, err := ParsePlayerQuery(bad[0], bad[1], bad[2]); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%v taken", bad)
		}
	}
	small, _ := ParsePlayerQuery("0100000000000000000000000000000000000000000000000000000000000000", "1760900100",
		query.Get("sig"))
	if err := small.Check(LinkLabel, "39f713d0a644253f", at, LinkWindow); !errors.Is(err, ErrSmallOrder) {
		t.Fatalf("a small-order key: %v", err)
	}
	if code := LinkCode(q.Key, q.TS); len(code) != 7 || code[3] != '-' {
		t.Fatalf("code %q", code)
	}
}

func TestPass(t *testing.T) {
	master := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	player := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	public := master.Public().(ed25519.PublicKey)
	b := MakePass(master, Pass{Flags: PassFlagGuild, MasterKeyID: KeyIDBytes(public),
		Player: player.Public().(ed25519.PublicKey), DiscordID: 80351110224678912,
		DiscordName: "nelly\x01é" + string(bytes.Repeat([]byte("x"), 40)), Issued: 1760900200, Expires: 1761159400})
	if len(b) != PassSize {
		t.Fatal(len(b))
	}
	p, err := ReadPass(b, public)
	if err != nil {
		t.Fatal(err)
	}
	if p.DiscordID != 80351110224678912 || len(p.DiscordName) != 32 || p.DiscordName[:8] != "nelly???" ||
		p.Flags != 1 || p.Expires != 1761159400 {
		t.Fatalf("%+v", p)
	}
	b[55] ^= 1
	if _, err := ReadPass(b, public); err == nil {
		t.Fatal("an altered pass taken")
	}
	if _, err := ReadPass(b[:169], public); err == nil {
		t.Fatal("a short pass taken")
	}
}
