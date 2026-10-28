// Package vectors makes testdata/vectors.json: fixed keys and the ids,
// signatures, probes, listings and signed bodies the protocol derives from
// them, for other implementations (the game's C code, the reference
// publisher) to test against. vectors_test.go checks the file still
// matches, and rewrites it with -update.
package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// Key is a key pair and its ids.
type Key struct {
	Seed       string `json:"seed"`
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"`
	KeyIDBytes string `json:"key_id_bytes"`
}

// Request is a signed request.
type Request struct {
	// the receiving master's key id, the canonical string's second line
	MasterKeyID   string `json:"master_key_id"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	TS            string `json:"ts"`
	Nonce         string `json:"nonce"`
	Body          string `json:"body"`
	BodySHA256    string `json:"body_sha256"`
	Canonical     string `json:"canonical"`
	Signature     string `json:"signature"`
	Authorization string `json:"authorization"`
}

// Probe is a probe and its answer.
type Probe struct {
	MasterKeyID   string `json:"master_key_id"`
	Nonce         string `json:"nonce"`
	Packet        string `json:"packet"`
	SignedMessage string `json:"signed_message"`
	Answer        string `json:"answer"`
}

// ListingVector is a listing, its bytes and what a reader takes from it.
type ListingVector struct {
	Description    string `json:"description"`
	HostSeed       string `json:"host_seed"`
	HostPublicKey  string `json:"host_public_key"`
	NetworkVersion int    `json:"network_version"`
	Flags          int    `json:"flags"`
	Sequence       uint32 `json:"sequence"`
	Time           uint32 `json:"time"`
	Token          string `json:"token,omitempty"`
	Sealed         string `json:"sealed_token,omitempty"`
	Players        int    `json:"players"`
	MaxPlayers     int    `json:"max_players"`
	Engine         int    `json:"engine"`
	Name           string `json:"name"`
	Map            string `json:"map"`
	Gametype       string `json:"gametype"`
	Kind           int    `json:"kind"`
	Bytes          string `json:"bytes"`
	Base64         string `json:"base64"`
	Size           int    `json:"size"`
	SignedSize     int    `json:"signed_size"`
	SignedMessage  string `json:"signed_message"`
	Signature      string `json:"signature"`
	Valid          bool   `json:"valid"`
}

// SignedBody is a body with its signature headers.
type SignedBody struct {
	Body          string `json:"body"`
	Signature     string `json:"signature_header"`
	SignatureKey  string `json:"signature_key_header"`
	SignatureTime string `json:"signature_time_header"`
	ETag          string `json:"etag"`
}

// File is the vectors file.
type File struct {
	Comment       string          `json:"comment"`
	Protocol      int             `json:"protocol"`
	Publisher     Key             `json:"publisher"`
	Master        Key             `json:"master"`
	Host          Key             `json:"host"`
	Instance      string          `json:"instance"`
	ServerIDInput string          `json:"server_id_input"`
	ServerID      string          `json:"server_id"`
	Publish       Request         `json:"publish_request"`
	Me            Request         `json:"me_request"`
	Probe         Probe           `json:"probe"`
	Listings      []ListingVector `json:"listings"`
	List          SignedBody      `json:"list"`
	SmallOrderKey string          `json:"small_order_key_refused"`
	ProofNonce    string          `json:"proof_nonce"`
	ProofSig      string          `json:"proof_signature_hex"`
	Player        Key             `json:"player"`
	Link          PlayerQuery     `json:"link"`
	PassRequest   PlayerQuery     `json:"pass_request"`
	Pass          PassVector      `json:"pass"`
	PassProof     PassProof       `json:"pass_proof"`
	PassesRefused []RefusedPass   `json:"passes_refused"`
	Netlist       NetlistVector   `json:"netlist"`
}

// PlayerQuery is a player key's signed query: a link page's, or a pass
// request's (Code: the link's confirmation code only).
type PlayerQuery struct {
	MasterKeyID string `json:"master_key_id"`
	TS          string `json:"ts"`
	SignedText  string `json:"signed_text"`
	Sig         string `json:"sig"`
	Query       string `json:"query"`
	Code        string `json:"code,omitempty"`
}

// PassVector is a pass, its fields and the message the master signed.
type PassVector struct {
	Flags           int    `json:"flags"`
	MasterKeyID     string `json:"master_key_id"`
	PlayerPublicKey string `json:"player_public_key"`
	// decimal: a JSON number would not hold a snowflake in every reader
	DiscordID     string `json:"discord_id"`
	DiscordName   string `json:"discord_name"`
	Issued        int64  `json:"issued"`
	Expires       int64  `json:"expires"`
	SignedMessage string `json:"signed_message"`
	Signature     string `json:"signature"`
	Bytes         string `json:"bytes"`
}

// PassProof is the proof at a server's door: through the tunnel (its
// session secret's binding), and on a LAN (a binding of zeros).
type PassProof struct {
	SessionSecret string `json:"session_secret"`
	Binding       string `json:"binding"`
	Message       string `json:"message"`
	Proof         string `json:"proof"`
	LANBinding    string `json:"lan_binding"`
	LANMessage    string `json:"lan_message"`
	LANProof      string `json:"lan_proof"`
}

// RefusedPass is a pass a server must refuse.
type RefusedPass struct {
	Name  string `json:"name"`
	Bytes string `json:"bytes"`
	Why   string `json:"why"`
}

// NetlistVector is a netlist: its ranges, body and headers, and bodies a
// reader must refuse.
type NetlistVector struct {
	Ranges          [][2]string      `json:"ranges"`
	Generated       uint64           `json:"generated"`
	Serial          uint64           `json:"serial"`
	Body            string           `json:"body"`
	Signature       string           `json:"signature"`
	SignatureHeader string           `json:"signature_header"`
	ETag            string           `json:"etag"`
	Refused         []RefusedNetlist `json:"refused"`
}

// RefusedNetlist is a netlist body a reader must refuse.
type RefusedNetlist struct {
	Name string `json:"name"`
	Body string `json:"body"`
	Why  string `json:"why"`
}

func seed(hexText string) ed25519.PrivateKey {
	raw, _ := hex.DecodeString(hexText)
	return ed25519.NewKeyFromSeed(raw)
}

func key(private ed25519.PrivateKey) Key {
	public := private.Public().(ed25519.PublicKey)
	id := sign.KeyIDBytes(public)
	return Key{Seed: sign.SeedText(private), PublicKey: sign.PublicKeyText(public), KeyID: sign.KeyID(public),
		KeyIDBytes: hex.EncodeToString(id[:])}
}

func request(private ed25519.PrivateKey, masterKeyID, method, path, ts, nonce string, body []byte) Request {
	canonical := sign.Canonical(masterKeyID, method, path, ts, nonce, body)
	signature := ed25519.Sign(private, []byte(canonical))
	n, _ := strconv.ParseInt(ts, 10, 64)
	return Request{MasterKeyID: masterKeyID, Method: method, Path: path, TS: ts, Nonce: nonce, Body: string(body), BodySHA256: sign.BodyHash(body),
		Canonical: canonical, Signature: base64.StdEncoding.EncodeToString(signature),
		Authorization: sign.Authorization(private, masterKeyID, method, path, body, time.Unix(n, 0), nonce)}
}

func listingVector(description string, host ed25519.PrivateKey, f listing.Fields) ListingVector {
	bytes := listing.Make(host, f)
	l, err := listing.Read(bytes)
	v := ListingVector{
		Description: description, HostSeed: sign.SeedText(host),
		HostPublicKey: hex.EncodeToString(host.Public().(ed25519.PublicKey)), NetworkVersion: f.NetworkVersion,
		Flags: f.Flags, Sequence: f.Sequence, Time: f.Time, Players: f.Players, MaxPlayers: f.MaxPlayers,
		Engine: f.Engine, Name: f.Name, Map: f.Map, Gametype: f.Gametype, Kind: f.Kind,
		Bytes: hex.EncodeToString(bytes), Base64: base64.StdEncoding.EncodeToString(bytes), Size: len(bytes),
		Valid: err == nil,
	}
	if f.Flags&listing.FlagPassword != 0 {
		v.Sealed = hex.EncodeToString(f.Sealed)
	} else {
		v.Token = hex.EncodeToString(f.Token[:])
	}
	if l != nil {
		v.SignedSize = l.SignedSize
		v.SignedMessage = hex.EncodeToString(append([]byte(listing.SignatureLabel), bytes[:l.SignedSize]...))
		v.Signature = hex.EncodeToString(l.Signature)
	}
	return v
}

// Marshal writes the vectors as the file holds them: indented, ASCII, with
// '&' as it is (not escaped for HTML, as a query has it).
func Marshal(f File) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(f)
	return buffer.Bytes(), err
}

// Generate makes the vectors.
func Generate() File {
	publisher := seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	master := seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	host := seed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	publisherKey, masterKey := key(publisher), key(master)
	instance := "main"
	serverID := sign.ServerID(publisherKey.KeyID, instance)

	var token [listing.TokenSize]byte
	for i := range token {
		token[i] = byte(0xa0 + i)
	}
	plain := listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen | listing.FlagTeams | listing.FlagDedicated,
		Sequence: 412, Time: 1760900000, Token: token, Players: 5, MaxPlayers: 16, Engine: 1,
		Name: "OpenCE Dedicated", Map: "bloodgulch", Gametype: "CTF", Kind: 0}
	listingBytes := listing.Make(host, plain)
	// (made by p2p_seal_token's construction, XChaCha20-Poly1305, with the
	// password key 0x01 * 32 and the nonce 0x02 * 24; the master reads it
	// as 56 opaque bytes)
	sealed, _ := hex.DecodeString(SealedToken)
	password := listing.Fields{NetworkVersion: 38, Flags: listing.FlagOpen | listing.FlagInProgress |
		listing.FlagPassword, Sequence: 7, Time: 1760900030, Sealed: sealed, Players: 3, MaxPlayers: 8, Engine: 2,
		Name: "Hardcore SWAT", Map: "prisoner", Gametype: "Team Slayer", Kind: 0x81}
	closed := listing.Fields{NetworkVersion: 38, Flags: listing.FlagClosed, Sequence: 413, Time: 1760900100,
		Players: 0, MaxPlayers: 16, Engine: 1, Name: "OpenCE Dedicated", Map: "bloodgulch", Gametype: "CTF"}
	corrupted := listingVector("a listing whose name was changed after signing: it must be refused", host, plain)
	raw, _ := hex.DecodeString(corrupted.Bytes)
	raw[2+1+2+1+4+4+32+16+3+1] ^= 0x20
	corrupted.Bytes, corrupted.Base64 = hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw)
	_, err := listing.Read(raw)
	corrupted.Valid = err == nil
	corrupted.Name = "oPenCE Dedicated"

	body, _ := json.Marshal(map[string]any{
		"protocol": 1, "instance": instance, "name": "OpenCE Dedicated", "map": "bloodgulch", "gametype": "CTF",
		"variant": "CTF", "players": 5, "max_players": 16, "teams": true, "in_progress": false, "password": false,
		"dedicated": true, "network_version": 38, "build": "build-206", "region": "eu", "tunnel_port": 2302,
		"listing": base64.StdEncoding.EncodeToString(listingBytes), "closed": false, "serial": 412,
	})

	var nonce [probe.NonceSize]byte
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
	}
	masterID := sign.KeyIDBytes(master.Public().(ed25519.PublicKey))

	listBody := []byte(`{"protocol":1,"master":{"name":"OpenCE Master 1","key_id":"` + masterKey.KeyID +
		`","time":1760900000},"servers":[]}`)
	digest := sha256.Sum256(listBody)

	proofNonce := "opence-apply-1760900000-0123456789abcdef"
	player := seed(PlayerSeed)
	pass := sign.Pass{Flags: sign.PassFlagGuild, MasterKeyID: masterID, Player: player.Public().(ed25519.PublicKey),
		DiscordID: 80351110224678912, DiscordName: "nelly", Issued: 1760900200, Expires: 1760900200 + 259200}
	passBytes := sign.MakePass(master, pass)
	return File{
		Comment: "OpenCE master protocol v1 test vectors (docs/master_protocol.md). Hex is lowercase; " +
			"strings are ASCII. Made by github.com/OpenCommunityEdition/opence-master-server/internal/vectors.",
		Protocol: 1, Publisher: publisherKey, Master: masterKey, Host: key(host), Instance: instance,
		ServerIDInput: publisherKey.KeyID + instance, ServerID: serverID,
		Publish: request(publisher, masterKey.KeyID, "PUT", "/v1/servers/"+serverID, "1760900000", "000102030405060708090a0b0c0d0e0f",
			body),
		Me: request(publisher, masterKey.KeyID, "GET", "/v1/me", "1760900001", "f0e0d0c0b0a090807060504030201000", nil),
		Probe: Probe{MasterKeyID: hex.EncodeToString(masterID[:]), Nonce: hex.EncodeToString(nonce[:]),
			Packet:        hex.EncodeToString(probe.Probe(masterID, nonce)),
			SignedMessage: hex.EncodeToString(probe.SignedMessage(masterID, nonce)),
			Answer:        hex.EncodeToString(probe.Answer(publisher, masterID, nonce))},
		Listings: []ListingVector{
			listingVector("an open team game of a dedicated server (flags open, teams, dedicated)", host, plain),
			listingVector("a password game in progress: its token sealed (56 bytes); kind 0x81 is SWAT with Hardcore",
				host, password),
			listingVector("a tombstone: the host stopped (flags closed, token zero)", host, closed),
			corrupted,
		},
		List: SignedBody{Body: string(listBody), Signature: sign.SignBody(master, listBody), SignatureKey: masterKey.KeyID,
			SignatureTime: "1760900000", ETag: `"` + hex.EncodeToString(digest[:8]) + `"`},
		SmallOrderKey: sign.PublicKeyPrefix + "0100000000000000000000000000000000000000000000000000000000000000",
		ProofNonce:    proofNonce,
		ProofSig:      hex.EncodeToString(ed25519.Sign(publisher, []byte(proofNonce))),
		Player:        key(player),
		Link:          playerQuery(player, sign.LinkLabel, masterKey.KeyID, 1760900100, true),
		PassRequest:   playerQuery(player, sign.PassGetLabel, masterKey.KeyID, 1760900200, false),
		Pass:          passVector(master, pass, passBytes),
		PassProof:     passProof(player, passBytes),
		PassesRefused: refusedPasses(master, publisher, pass, passBytes),
		Netlist:       netlistVector(master),
	}
}

// PlayerSeed is the vectors' player key's seed.
const PlayerSeed = "8b8d38ea4ccbb4f2a3fbd5a1c6b4a2b8a9e5b7c7d1f0e3a2b4c6d8e0f1a3b5c7"

func playerQuery(player ed25519.PrivateKey, label, masterKeyID string, ts int64, link bool) PlayerQuery {
	public := player.Public().(ed25519.PublicKey)
	text := strconv.FormatInt(ts, 10)
	signed := sign.PlayerSignedText(label, masterKeyID, hex.EncodeToString(public), text)
	q := PlayerQuery{MasterKeyID: masterKeyID, TS: text, SignedText: signed,
		Sig: hex.EncodeToString(ed25519.Sign(player, []byte(signed))), Query: sign.SignPlayerQuery(player, label,
			masterKeyID, ts)}
	if link {
		q.Code = sign.LinkCode(public, text)
	}
	return q
}

func passVector(master ed25519.PrivateKey, p sign.Pass, b []byte) PassVector {
	return PassVector{Flags: int(p.Flags), MasterKeyID: hex.EncodeToString(p.MasterKeyID[:]),
		PlayerPublicKey: hex.EncodeToString(p.Player), DiscordID: strconv.FormatUint(p.DiscordID, 10),
		DiscordName: p.DiscordName, Issued: p.Issued, Expires: p.Expires,
		SignedMessage: hex.EncodeToString(sign.PassMessage(b[:sign.PassSigned])),
		Signature:     hex.EncodeToString(b[sign.PassSigned:]), Bytes: hex.EncodeToString(b)}
}

// proofMessage is what the player key signs at a server's door: the label,
// SHA-256 of the pass, and the connection's binding.
func proofMessage(pass, binding []byte) []byte {
	digest := sha256.Sum256(pass)
	return append(append([]byte(sign.ProofLabel), digest[:]...), binding...)
}

func passProof(player ed25519.PrivateKey, pass []byte) PassProof {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sign.BindingLabel))
	binding := mac.Sum(nil)
	lan := make([]byte, 32)
	message, lanMessage := proofMessage(pass, binding), proofMessage(pass, lan)
	return PassProof{SessionSecret: hex.EncodeToString(secret), Binding: hex.EncodeToString(binding),
		Message: hex.EncodeToString(message), Proof: hex.EncodeToString(ed25519.Sign(player, message)),
		LANBinding: hex.EncodeToString(lan), LANMessage: hex.EncodeToString(lanMessage),
		LANProof: hex.EncodeToString(ed25519.Sign(player, lanMessage))}
}

// resign signs a pass's first 106 bytes again with a key.
func resign(key ed25519.PrivateKey, b []byte) []byte {
	out := append([]byte(nil), b...)
	copy(out[sign.PassSigned:], ed25519.Sign(key, sign.PassMessage(out[:sign.PassSigned])))
	return out
}

func refusedPasses(master, publisher ed25519.PrivateKey, p sign.Pass, b []byte) []RefusedPass {
	altered := append([]byte(nil), b...)
	altered[57] ^= 0x01
	magic := append([]byte(nil), b...)
	magic[7] = 'X'
	format := append([]byte(nil), b...)
	format[8] = 2
	other := append([]byte(nil), b...)
	publisherID := sign.KeyIDBytes(publisher.Public().(ed25519.PublicKey))
	copy(other[10:18], publisherID[:])
	return []RefusedPass{
		{"altered discord id", hex.EncodeToString(altered),
			"the Discord id's last byte changed after signing: the master's signature fails"},
		{"wrong magic", hex.EncodeToString(resign(master, magic)), "OPCEPASX, not OPCEPASS (signed again by the master)"},
		{"format 2", hex.EncodeToString(resign(master, format)), "format 2, not 1 (signed again by the master)"},
		{"signed by the publisher key", hex.EncodeToString(resign(publisher, b)),
			"signed by the vectors' publisher key instead of the master key: the master's signature fails"},
		{"another master's key id", hex.EncodeToString(resign(master, other)),
			"its master key id is the publisher key's, not a pinned master's (signed by the master)"},
		{"truncated", hex.EncodeToString(b[:sign.PassSize-1]), "169 bytes, not 170"},
	}
}

func netlistVector(master ed25519.PrivateKey) NetlistVector {
	texts := [][2]string{{"1.2.3.0", "1.2.3.255"}, {"5.6.7.8", "5.6.7.8"}, {"45.0.0.0", "45.15.255.255"},
		{"185.220.100.0", "185.220.103.255"}}
	var ranges []netlist.Range
	for _, t := range texts {
		first, _ := netlist.Number(netip.MustParseAddr(t[0]))
		last, _ := netlist.Number(netip.MustParseAddr(t[1]))
		ranges = append(ranges, netlist.Range{First: first, Last: last})
	}
	const generated, serial = 1760900000, 7
	body := netlist.Encode(ranges, generated, serial)
	header := sign.SignBody(master, body)
	signature, _ := base64.StdEncoding.DecodeString(header[len("ed25519="):])
	r := func(first, last string) netlist.Range {
		f, _ := netlist.Number(netip.MustParseAddr(first))
		l, _ := netlist.Number(netip.MustParseAddr(last))
		return netlist.Range{First: f, Last: l}
	}
	bad := func(change func([]byte) []byte) string {
		return hex.EncodeToString(change(append([]byte(nil), body...)))
	}
	encode := func(list ...netlist.Range) string { return hex.EncodeToString(netlist.Encode(list, generated, serial)) }
	return NetlistVector{Ranges: texts, Generated: generated, Serial: serial, Body: hex.EncodeToString(body),
		Signature: hex.EncodeToString(signature), SignatureHeader: header, ETag: netlist.ETag(body),
		Refused: []RefusedNetlist{
			{"overlapping", encode(r("1.2.3.0", "1.2.3.255"), r("1.2.3.128", "1.2.4.10")),
				"the second range starts inside the first"},
			{"touching", encode(r("1.2.3.0", "1.2.3.255"), r("1.2.4.0", "1.2.4.255")),
				"the second range starts right after the first: merged lists never touch"},
			{"out of order", encode(r("5.6.7.8", "5.6.7.8"), r("1.2.3.0", "1.2.3.255")), "the ranges are not ascending"},
			{"wrong size", bad(func(b []byte) []byte { return b[:len(b)-1] }),
				"a byte short of 32 + 8 * count"},
			{"reserved byte set", bad(func(b []byte) []byte { b[10] = 1; return b }), "byte 10 (reserved) is not zero"},
			{"wrong magic", bad(func(b []byte) []byte { b[0] = 'X'; return b }), "XPCENET1, not OPCENET1"},
			{"format 2", bad(func(b []byte) []byte { b[8] = 2; return b }), "format 2, not 1"},
			{"first after last", encode(r("1.2.3.255", "1.2.3.0")), "the range's first address is after its last"},
		}}
}

// SealedToken is the password listing's sealed token: nonce 0x02 * 24, then
// the MAC and the ciphertext of the token a0..af under the password key
// 0x01 * 32 with the host's signing key as additional data (Monocypher's
// crypto_aead_lock, as p2p_seal_token calls it).
const SealedToken = "020202020202020202020202020202020202020202020202830b7b34e4bfb2066a5a2b270ac905b26cc7944c0ed25aea08c8cb3adefdd731"
