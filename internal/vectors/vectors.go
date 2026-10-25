// Package vectors makes testdata/vectors.json: fixed keys and the ids,
// signatures, probes, listings and signed bodies the protocol derives from
// them, for other implementations (the game's C code, the reference
// publisher) to test against. vectors_test.go checks the file still
// matches, and rewrites it with -update.
package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/listing"
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
	}
}

// SealedToken is the password listing's sealed token: nonce 0x02 * 24, then
// the MAC and the ciphertext of the token a0..af under the password key
// 0x01 * 32 with the host's signing key as additional data (Monocypher's
// crypto_aead_lock, as p2p_seal_token calls it).
const SealedToken = "020202020202020202020202020202020202020202020202830b7b34e4bfb2066a5a2b270ac905b26cc7944c0ed25aea08c8cb3adefdd731"
