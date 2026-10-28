package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const path = "../../testdata/vectors.json"

// The checked-in vectors are what the code makes now: a change to either
// is a change to the protocol.
func TestVectorsFile(t *testing.T) {
	made, err := Marshal(Generate())
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(path, made, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/vectors -update)", err)
	}
	if !bytes.Equal(stored, made) {
		t.Fatal("testdata/vectors.json differs from what the code makes (run go test ./internal/vectors -update)")
	}
}

// The player's, the link's, the pass's and the netlist's vectors read as
// the game must read them: the good ones taken, the refused ones refused.
func TestPlayerAndNetlistVectors(t *testing.T) {
	var f File
	data, err := Marshal(Generate())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	master, _ := sign.ParsePublicKey(f.Master.PublicKey)
	player, _ := sign.ParsePublicKey(f.Player.PublicKey)
	for _, q := range []PlayerQuery{f.Link, f.PassRequest} {
		values, err := url.ParseQuery(q.Query)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := sign.ParsePlayerQuery(values.Get("key"), values.Get("ts"), values.Get("sig"))
		if err != nil || values.Get("sig") != q.Sig || values.Get("ts") != q.TS {
			t.Fatalf("%+v: %v", q, err)
		}
		label := strings.SplitN(q.SignedText, "\n", 2)[0]
		ts, _ := strconv.ParseInt(q.TS, 10, 64)
		if err := parsed.Check(label, f.Master.KeyID, time.Unix(ts, 0), sign.ClockWindow); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	if f.Link.Code != sign.LinkCode(player, f.Link.TS) || len(f.Link.Code) != 7 {
		t.Fatalf("code %q", f.Link.Code)
	}
	raw, _ := hex.DecodeString(f.Pass.Bytes)
	pass, err := sign.ReadPass(raw, master)
	if err != nil || pass.DiscordName != "nelly" || strconv.FormatUint(pass.DiscordID, 10) != f.Pass.DiscordID ||
		pass.Expires != f.Pass.Expires || len(raw) != 170 {
		t.Fatalf("%+v %v", pass, err)
	}
	signed, _ := hex.DecodeString(f.Pass.SignedMessage)
	if len(signed) != 13+106 || !bytes.Equal(signed[13:], raw[:106]) {
		t.Fatal("the pass's signed message")
	}
	for _, refused := range f.PassesRefused {
		raw, _ := hex.DecodeString(refused.Bytes)
		if _, err := sign.ReadPass(raw, master); err == nil {
			t.Errorf("pass %q taken", refused.Name)
		}
	}
	digest := sha256.Sum256(raw)
	for _, c := range []struct{ binding, message, proof string }{
		{f.PassProof.Binding, f.PassProof.Message, f.PassProof.Proof},
		{f.PassProof.LANBinding, f.PassProof.LANMessage, f.PassProof.LANProof},
	} {
		message, _ := hex.DecodeString(c.message)
		binding, _ := hex.DecodeString(c.binding)
		proof, _ := hex.DecodeString(c.proof)
		want := append(append([]byte("opence-pass-proof-1"), digest[:]...), binding...)
		if !bytes.Equal(message, want) || !ed25519.Verify(player, message, proof) {
			t.Fatal("a proof")
		}
	}
	body, _ := hex.DecodeString(f.Netlist.Body)
	list, err := netlist.Decode(body)
	if err != nil || list.Serial != f.Netlist.Serial || len(list.Ranges) != len(f.Netlist.Ranges) ||
		!sign.VerifyBody(master, f.Netlist.SignatureHeader, body) {
		t.Fatalf("%+v %v", list, err)
	}
	for _, refused := range f.Netlist.Refused {
		raw, _ := hex.DecodeString(refused.Body)
		if _, err := netlist.Decode(raw); err == nil {
			t.Errorf("netlist %q taken", refused.Name)
		}
	}
}
