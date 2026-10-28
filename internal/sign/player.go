package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"time"
)

// The labels of what a player key signs, and of the master's pass
// (docs/master_protocol.md, "Player keys, links and passes").
const (
	// a link page's query
	LinkLabel = "opence-link-1"
	// a pass's request
	PassGetLabel = "opence-pass-get-1"
	// the master's signature of a pass
	PassLabel = "opence-pass-1"
	// the player's proof at a server's door
	ProofLabel = "opence-pass-proof-1"
	// the connection's binding the proof carries
	BindingLabel = "opence-link-binding-1"
)

// LinkWindow is how far a link's ts may be from the master's clock (a pass
// request's: ClockWindow).
const LinkWindow = 600 * time.Second

var hexSignature = regexp.MustCompile(`^[0-9a-f]{128}$`)

// The refusals of a player's signed query.
var (
	// a parameter missing or malformed, or the signature failing
	ErrBadSignature = errors.New("the signature does not verify")
	// ts too far from the master's clock
	ErrClock = errors.New("ts is too far from the master's clock")
	// a key whose signatures anyone can make
	ErrSmallOrder = errors.New("the key has a small order")
)

// PlayerQuery is a player's signed query: key, ts and sig.
type PlayerQuery struct {
	Key ed25519.PublicKey
	// the key in hexadecimal and ts, as sent (what was signed)
	KeyHex, TS string
	Time       int64
	Signature  []byte
}

// PlayerSignedText is what a player key signs for a query: the label, the
// master's key id, the public key in hexadecimal and ts, joined by line
// feeds.
func PlayerSignedText(label, masterKeyID, publicHex, ts string) string {
	return label + "\n" + masterKeyID + "\n" + publicHex + "\n" + ts
}

// ParsePlayerQuery reads a query's key (64 lowercase hexadecimal digits),
// ts (decimal) and sig (128 lowercase hexadecimal digits); ErrBadSignature
// for a malformed one.
func ParsePlayerQuery(key, ts, sig string) (PlayerQuery, error) {
	var q PlayerQuery
	if !hexKey.MatchString(key) || !decimalTS.MatchString(ts) || !hexSignature.MatchString(sig) {
		return q, ErrBadSignature
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return q, ErrBadSignature
	}
	raw, _ := hex.DecodeString(key)
	q.Signature, _ = hex.DecodeString(sig)
	q.Key, q.KeyHex, q.TS, q.Time = ed25519.PublicKey(raw), key, ts, n
	return q, nil
}

// Check checks a query for a label at the master whose key id is
// masterKeyID: ts within window of now (ErrClock), a key of large order
// (ErrSmallOrder), and the signature (ErrBadSignature).
func (q PlayerQuery) Check(label, masterKeyID string, now time.Time, window time.Duration) error {
	difference := now.Unix() - q.Time
	if difference < 0 {
		difference = -difference
	}
	if difference > int64(window/time.Second) {
		return ErrClock
	}
	if SmallOrder(q.Key) {
		return ErrSmallOrder
	}
	if !ed25519.Verify(q.Key, []byte(PlayerSignedText(label, masterKeyID, q.KeyHex, q.TS)), q.Signature) {
		return ErrBadSignature
	}
	return nil
}

// SignPlayerQuery makes a player's query for a label: "key=…&ts=…&sig=…".
func SignPlayerQuery(private ed25519.PrivateKey, label, masterKeyID string, ts int64) string {
	public := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	text := strconv.FormatInt(ts, 10)
	signature := ed25519.Sign(private, []byte(PlayerSignedText(label, masterKeyID, public, text)))
	return "key=" + public + "&ts=" + text + "&sig=" + hex.EncodeToString(signature)
}

// LinkCode is the confirmation code the game and the link page show: the
// first 6 characters of the base32 (A-Z, 2-7) of SHA-256 of the public
// key's 32 bytes and ts's text, as "ABC-DEF".
func LinkCode(public ed25519.PublicKey, ts string) string {
	digest := sha256.Sum256(append(append([]byte(nil), public...), ts...))
	text := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	return text[:3] + "-" + text[3:6]
}

// The pass's form.
const (
	PassMagic  = "OPCEPASS"
	PassFormat = 1
	PassSize   = 170
	// the bytes the master's signature covers (after PassLabel)
	PassSigned = 106
	// the pass's flag: the account is in the master's Discord server
	PassFlagGuild = 1
	// the Discord username's bytes
	PassNameSize = 32
)

// Pass is a player's pass: which Discord account holds the key, signed by
// the master.
type Pass struct {
	Flags       byte
	MasterKeyID [8]byte
	Player      ed25519.PublicKey
	DiscordID   uint64
	// ASCII, 32 bytes at most (PassName)
	DiscordName string
	Issued      int64
	Expires     int64
	Signature   []byte
}

// PassName is a Discord username as a pass holds it: each byte outside
// 0x20 to 0x7E made '?', cut to 32 bytes.
func PassName(name string) string {
	b := []byte(name)
	if len(b) > PassNameSize {
		b = b[:PassNameSize]
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// PassMessage is what the master signs of a pass's first 106 bytes: the
// label, then those bytes.
func PassMessage(signed []byte) []byte {
	return append([]byte(PassLabel), signed...)
}

// MakePass writes and signs a pass (170 bytes): the magic, the format,
// the flags, the master's key id, the player's key, the Discord id and
// username, the times, then the master's signature.
func MakePass(master ed25519.PrivateKey, p Pass) []byte {
	b := make([]byte, PassSize)
	copy(b, PassMagic)
	b[8] = PassFormat
	b[9] = p.Flags
	copy(b[10:18], p.MasterKeyID[:])
	copy(b[18:50], p.Player)
	binary.BigEndian.PutUint64(b[50:58], p.DiscordID)
	copy(b[58:90], PassName(p.DiscordName))
	binary.BigEndian.PutUint64(b[90:98], uint64(p.Issued))
	binary.BigEndian.PutUint64(b[98:106], uint64(p.Expires))
	copy(b[106:], ed25519.Sign(master, PassMessage(b[:PassSigned])))
	return b
}

// ReadPass reads a pass and checks its signature with a master's key, as
// a server does (but for its times and the proof).
func ReadPass(b []byte, master ed25519.PublicKey) (*Pass, error) {
	if len(b) != PassSize {
		return nil, errors.New("a pass is 170 bytes")
	}
	if string(b[:8]) != PassMagic {
		return nil, errors.New("not " + PassMagic)
	}
	if b[8] != PassFormat {
		return nil, errors.New("not format 1")
	}
	p := &Pass{Flags: b[9], Player: ed25519.PublicKey(append([]byte(nil), b[18:50]...)),
		DiscordID: binary.BigEndian.Uint64(b[50:58]), Issued: int64(binary.BigEndian.Uint64(b[90:98])),
		Expires: int64(binary.BigEndian.Uint64(b[98:106])), Signature: append([]byte(nil), b[106:]...)}
	copy(p.MasterKeyID[:], b[10:18])
	name := b[58:90]
	for len(name) > 0 && name[len(name)-1] == 0 {
		name = name[:len(name)-1]
	}
	p.DiscordName = string(name)
	if p.MasterKeyID != KeyIDBytes(master) {
		return nil, errors.New("another master's pass")
	}
	if !ed25519.Verify(master, PassMessage(b[:PassSigned]), p.Signature) {
		return nil, errors.New("the master's signature does not verify")
	}
	return p, nil
}
