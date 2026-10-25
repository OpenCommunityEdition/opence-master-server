package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func testKey() ed25519.PrivateKey {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	return ed25519.NewKeyFromSeed(seed)
}

func TestCanonicalString(t *testing.T) {
	got := Canonical("39f713d0a644253f", "PUT", "/v1/servers/0123456789abcdef", "1760900000",
		"000102030405060708090a0b0c0d0e0f", []byte(`{"a":1}`))
	want := "OpenCE-Master-v1\n39f713d0a644253f\nPUT\n/v1/servers/0123456789abcdef\n1760900000\n" +
		"000102030405060708090a0b0c0d0e0f\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
	if got != want {
		t.Fatalf("canonical:\n%q\nwant\n%q", got, want)
	}
	// an empty body hashes as SHA-256 of no bytes
	if BodyHash(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty body hash")
	}
}

func TestAuthorizationRoundTrip(t *testing.T) {
	key := testKey()
	public := key.Public().(ed25519.PublicKey)
	now := time.Unix(1760900000, 0)
	body := []byte(`{"protocol":1}`)
	const master = "39f713d0a644253f"
	header := Authorization(key, master, "PUT", "/v1/servers/x", body, now, "000102030405060708090a0b0c0d0e0f")
	auth, err := ParseAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if auth.KeyID != KeyID(public) || auth.Time != 1760900000 || auth.Nonce != "000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("parsed %+v", auth)
	}
	if !auth.Verify(public, master, "PUT", "/v1/servers/x", body) {
		t.Fatal("does not verify")
	}
	// a request signed for one master does not verify at another
	if auth.Verify(public, "0123456789abcdef", "PUT", "/v1/servers/x", body) {
		t.Fatal("verifies for another master")
	}
	for name, change := range map[string]func() (string, string, []byte){
		"method": func() (string, string, []byte) { return "DELETE", "/v1/servers/x", body },
		"path":   func() (string, string, []byte) { return "PUT", "/v1/servers/y", body },
		"body":   func() (string, string, []byte) { return "PUT", "/v1/servers/x", []byte(`{"protocol":2}`) },
	} {
		method, path, b := change()
		if auth.Verify(public, master, method, path, b) {
			t.Errorf("verifies with another %s", name)
		}
	}
	other, _ := NewSeed()
	if auth.Verify(other.Public().(ed25519.PublicKey), master, "PUT", "/v1/servers/x", body) {
		t.Error("verifies with another key")
	}
}

func TestParseAuthorizationRefusals(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	good := "keyid=0123456789abcdef, ts=1760900000, nonce=000102030405060708090a0b0c0d0e0f, sig=" + sig
	if _, err := ParseAuthorization(Scheme + " " + good); err != nil {
		t.Fatalf("good header refused: %v", err)
	}
	// any order, spaces optional
	if _, err := ParseAuthorization(Scheme + " sig=" + sig + ",nonce=000102030405060708090a0b0c0d0e0f," +
		"ts=1760900000 ,keyid=0123456789abcdef"); err != nil {
		t.Fatalf("reordered header refused: %v", err)
	}
	for name, header := range map[string]string{
		"no scheme":    good,
		"other scheme": "Bearer " + good,
		"short keyid":  Scheme + " " + strings.Replace(good, "0123456789abcdef", "0123", 1),
		"upper keyid":  Scheme + " " + strings.Replace(good, "0123456789abcdef", "0123456789ABCDEF", 1),
		"ts sign":      Scheme + " " + strings.Replace(good, "ts=1760900000", "ts=-1760900000", 1),
		"ts zero pad":  Scheme + " " + strings.Replace(good, "ts=1760900000", "ts=01760900000", 1),
		"short nonce":  Scheme + " " + strings.Replace(good, "000102030405060708090a0b0c0d0e0f", "0001", 1),
		"short sig":    Scheme + " " + strings.Replace(good, sig, base64.StdEncoding.EncodeToString(make([]byte, 63)), 1),
		"unpadded sig": Scheme + " " + strings.Replace(good, sig, strings.TrimRight(sig, "="), 1),
		"twice":        Scheme + " " + good + ", ts=1760900000",
		"missing":      Scheme + " keyid=0123456789abcdef, ts=1760900000",
		"unknown":      Scheme + " " + good + ", extra=1",
	} {
		if _, err := ParseAuthorization(header); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClockWindow(t *testing.T) {
	now := time.Unix(1760900000, 0)
	for _, c := range []struct {
		ts int64
		ok bool
	}{{1760900000, true}, {1760900300, true}, {1760899700, true}, {1760900301, false}, {1760899699, false}} {
		if got := (Auth{Time: c.ts}).InWindow(now); got != c.ok {
			t.Errorf("ts %d: %v, want %v", c.ts, got, c.ok)
		}
	}
}

func TestIDs(t *testing.T) {
	public := testKey().Public().(ed25519.PublicKey)
	if KeyID(public) != "21fe31dfa154a261" {
		t.Fatalf("key id %s", KeyID(public))
	}
	// the key id's 16 characters of text, then the instance
	if ServerID("21fe31dfa154a261", "main") != "4c5f15237c866f6f" {
		t.Fatalf("server id %s", ServerID("21fe31dfa154a261", "main"))
	}
	for _, ok := range []string{"main", "a", "eu-1", "ctf_2", strings.Repeat("a", 32)} {
		if !ValidInstance(ok) {
			t.Errorf("instance %q refused", ok)
		}
	}
	for _, bad := range []string{"", "-a", "_a", "Main", "a b", "a.b", strings.Repeat("a", 33)} {
		if ValidInstance(bad) {
			t.Errorf("instance %q accepted", bad)
		}
	}
}

func TestKeys(t *testing.T) {
	key := testKey()
	text := PublicKeyText(key.Public().(ed25519.PublicKey))
	if _, err := ParsePublicKey(text); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(strings.TrimPrefix(text, PublicKeyPrefix)); err != nil {
		t.Fatal("bare hex refused")
	}
	for _, bad := range []string{"ed25519:00", "ed25519:" + strings.Repeat("g", 64),
		// the identity point and a point of order 8: small order
		"ed25519:0100000000000000000000000000000000000000000000000000000000000000",
		"ed25519:c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	parsed, err := ParseSeed("# a comment\n\n" + SeedText(key) + "  # its seed\n")
	if err != nil || !parsed.Equal(key) {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := ParseSeed("abcd\n"); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestBodySignature(t *testing.T) {
	key := testKey()
	body := []byte(`{"protocol":1,"servers":[]}`)
	header := SignBody(key, body)
	if !strings.HasPrefix(header, "ed25519=") {
		t.Fatal(header)
	}
	public := key.Public().(ed25519.PublicKey)
	if !VerifyBody(public, header, body) {
		t.Fatal("does not verify")
	}
	if VerifyBody(public, header, append(body, ' ')) {
		t.Fatal("verifies another body")
	}
	if VerifyBody(public, strings.TrimPrefix(header, "ed25519="), body) {
		t.Fatal("verifies without its prefix")
	}
}
