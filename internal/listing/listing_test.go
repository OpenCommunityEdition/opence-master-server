package listing

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func host() ed25519.PrivateKey {
	seed, _ := hex.DecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	return ed25519.NewKeyFromSeed(seed)
}

func fields() Fields {
	return Fields{NetworkVersion: 38, Flags: FlagOpen | FlagTeams, Sequence: 9, Time: 1760900000, Players: 5,
		MaxPlayers: 16, Engine: 1, Name: "OpenCE Dedicated", Map: "bloodgulch", Gametype: "CTF", Kind: 0x80}
}

func TestReadWhatMakeWrites(t *testing.T) {
	bytes := Make(host(), fields())
	l, err := Read(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if l.NetworkVersion != 38 || !l.Open() || !l.Teams() || l.InProgress() || l.Password() || l.Closed() ||
		l.Dedicated() || l.Sequence != 9 || l.Time != 1760900000 || l.Players != 5 || l.MaxPlayers != 16 ||
		l.Engine != 1 || l.Name != "OpenCE Dedicated" || l.Map != "bloodgulch" || l.Gametype != "CTF" || l.Kind != 0x80 {
		t.Fatalf("read %+v", l)
	}
	if len(bytes) != 2+1+2+1+4+4+32+16+3+17+11+4+8+64 || l.SignedSize != len(bytes)-64 {
		t.Fatalf("size %d, signed %d", len(bytes), l.SignedSize)
	}
}

func TestPasswordAndDedicated(t *testing.T) {
	f := fields()
	f.Flags |= FlagPassword | FlagDedicated | FlagInProgress
	f.Sealed = make([]byte, SealedSize)
	for i := range f.Sealed {
		f.Sealed[i] = byte(i)
	}
	bytes := Make(host(), f)
	l, err := Read(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Password() || !l.Dedicated() || !l.InProgress() || len(l.Sealed) != SealedSize || l.Sealed[55] != 55 ||
		l.Token != [TokenSize]byte{} || l.Players != 5 || l.Name != "OpenCE Dedicated" {
		t.Fatalf("read %+v", l)
	}
}

func TestEveryAlteredByteIsRefused(t *testing.T) {
	bytes := Make(host(), fields())
	for i := range bytes {
		altered := append([]byte(nil), bytes...)
		altered[i] ^= 0x01
		if _, err := Read(altered); err == nil {
			t.Fatalf("byte %d altered: accepted", i)
		}
	}
}

func TestEveryCutIsRefused(t *testing.T) {
	bytes := Make(host(), fields())
	for n := 0; n < len(bytes); n++ {
		if _, err := Parse(bytes[:n]); err == nil {
			t.Fatalf("cut to %d: parsed", n)
		}
	}
	if _, err := Parse(append(bytes, 0)); err == nil {
		t.Fatal("a byte too many: parsed")
	}
}

func TestLimits(t *testing.T) {
	f := fields()
	f.Name, f.Map, f.Gametype = strings.Repeat("n", 40), strings.Repeat("m", 40), strings.Repeat("g", 40)
	f.Flags |= FlagPassword
	f.Sealed = make([]byte, SealedSize)
	bytes := Make(host(), f)
	// (the game's MAXIMUM_LISTING_SIZE and MINIMUM_LISTING_SIZE, p2p_lobby.c)
	if MaximumSize != 268 || MinimumSize != 140 {
		t.Fatalf("sizes %d to %d, not 140 to 268", MinimumSize, MaximumSize)
	}
	if len(bytes) != MaximumSize {
		t.Fatalf("the longest listing is %d, not %d", len(bytes), MaximumSize)
	}
	l, err := Read(bytes)
	if err != nil || len(l.Name) != 32 || len(l.Map) != 32 || len(l.Gametype) != 24 {
		t.Fatalf("%v %+v", err, l)
	}
	f = fields()
	f.Name, f.Map, f.Gametype = "", "", ""
	if bytes := Make(host(), f); len(bytes) != MinimumSize {
		t.Fatalf("the shortest listing is %d, not %d", len(bytes), MinimumSize)
	}
	// a length byte past its field's maximum
	long := Make(host(), fields())
	long[2+1+2+1+4+4+32+16+3] = 33
	if _, err := Parse(long); err == nil {
		t.Fatal("a 33-character name parsed")
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize([]byte("a\x01b\x7f\xffc\x00d"), 32); got != "a?b??c" {
		t.Fatalf("%q", got)
	}
	f := fields()
	f.Name = "tab\there"
	l, err := Read(Make(host(), f))
	if err != nil || l.Name != "tab?here" {
		t.Fatalf("%v %q", err, l.Name)
	}
}

func TestSmallOrderKeyRefused(t *testing.T) {
	bytes := Make(host(), fields())
	l, _ := Parse(bytes)
	// the identity point: any "signature" with R = identity and S = 0 verifies under it
	identity := make([]byte, 32)
	identity[0] = 1
	copy(bytes[14:46], identity)
	l, err := Parse(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(bytes); err != ErrKey {
		t.Fatalf("got %v", err)
	}
}
