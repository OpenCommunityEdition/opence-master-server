// Package listing reads the game's host-signed listing, the bytes
// port/linux/src/p2p_lobby.c (listing_make) publishes to the brokers and a
// dedicated server sends the master, and checks the host's signature.
//
// The layout, in network byte order:
//
//	"HL", format 1, network version (2), flags (1), sequence (4), Unix time (4),
//	the host's Ed25519 key (32), the invite's token (16) or, with the password
//	flag, the token sealed (56: nonce 24, MAC 16, ciphertext 16), players (1),
//	most players (1), the gametype's engine (1), name, map and gametype (a
//	length byte, then up to 32, 32 and 24 bytes), a stamp (8: the game's kind,
//	then 7 reserved), and the Ed25519 signature (64) of "hceu-lobby-1" and
//	every byte before it.
package listing

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

const (
	Format         = 1
	KeySize        = 32
	TokenSize      = 16
	SealedSize     = 24 + 16 + 16
	SignatureSize  = 64
	StampSize      = 8
	NameSize       = 32
	MapSize        = 32
	GametypeSize   = 24
	SignatureLabel = "hceu-lobby-1"

	FlagOpen       = 1
	FlagInProgress = 2
	FlagTeams      = 4
	FlagClosed     = 8
	FlagPassword   = 16
	// Set by a dedicated server (the plan's 4.9); the game does not send it yet.
	FlagDedicated = 32

	MinimumSize = 2 + 1 + 2 + 1 + 4 + 4 + KeySize + TokenSize + 3 + 3 + StampSize + SignatureSize
	MaximumSize = 2 + 1 + 2 + 1 + 4 + 4 + KeySize + SealedSize + 3 + (1 + NameSize) + (1 + MapSize) +
		(1 + GametypeSize) + StampSize + SignatureSize
)

// Listing is a listing read.
type Listing struct {
	NetworkVersion int
	Flags          int
	Sequence       uint32
	Time           uint32
	Key            ed25519.PublicKey
	// the invite's token, or zero with FlagPassword
	Token [TokenSize]byte
	// with FlagPassword: the token sealed with the password's key
	Sealed     []byte
	Players    int
	MaxPlayers int
	Engine     int
	Name       string
	Map        string
	Gametype   string
	Kind       int
	Stamp      [StampSize]byte
	SignedSize int
	Signature  []byte
}

func (l *Listing) Open() bool       { return l.Flags&FlagOpen != 0 }
func (l *Listing) InProgress() bool { return l.Flags&FlagInProgress != 0 }
func (l *Listing) Teams() bool      { return l.Flags&FlagTeams != 0 }
func (l *Listing) Closed() bool     { return l.Flags&FlagClosed != 0 }
func (l *Listing) Password() bool   { return l.Flags&FlagPassword != 0 }
func (l *Listing) Dedicated() bool  { return l.Flags&FlagDedicated != 0 }

var (
	ErrMalformed = errors.New("the listing is malformed")
	ErrSignature = errors.New("the listing's signature does not verify")
	ErrKey       = errors.New("the listing's key has a small order")
)

// Sanitize keeps printable ASCII (others become '?') and cuts to size, as
// the game's sanitize does.
func Sanitize(text []byte, maximum int) string {
	if len(text) > maximum {
		text = text[:maximum]
	}
	out := make([]byte, 0, len(text))
	for _, c := range text {
		if c == 0 {
			break
		}
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// SanitizeString is Sanitize for a string.
func SanitizeString(text string, maximum int) string {
	return Sanitize([]byte(text), maximum)
}

func text(bytes []byte, offset *int, maximum int) (string, bool) {
	if *offset >= len(bytes) {
		return "", false
	}
	length := int(bytes[*offset])
	*offset++
	if length > maximum || *offset+length > len(bytes) {
		return "", false
	}
	value := Sanitize(bytes[*offset:*offset+length], maximum)
	*offset += length
	return value, true
}

// Parse reads a listing without checking its signature, as listing_read.
func Parse(bytes []byte) (*Listing, error) {
	if len(bytes) < MinimumSize || len(bytes) > MaximumSize || bytes[0] != 'H' || bytes[1] != 'L' ||
		bytes[2] != Format {
		return nil, ErrMalformed
	}
	l := &Listing{}
	offset := 3
	l.NetworkVersion = int(binary.BigEndian.Uint16(bytes[offset:]))
	offset += 2
	l.Flags = int(bytes[offset])
	offset++
	l.Sequence = binary.BigEndian.Uint32(bytes[offset:])
	offset += 4
	l.Time = binary.BigEndian.Uint32(bytes[offset:])
	offset += 4
	l.Key = append(ed25519.PublicKey(nil), bytes[offset:offset+KeySize]...)
	offset += KeySize
	if l.Flags&FlagPassword != 0 {
		if offset+SealedSize+3 > len(bytes) {
			return nil, ErrMalformed
		}
		l.Sealed = append([]byte(nil), bytes[offset:offset+SealedSize]...)
		offset += SealedSize
	} else {
		copy(l.Token[:], bytes[offset:offset+TokenSize])
		offset += TokenSize
	}
	l.Players = int(bytes[offset])
	l.MaxPlayers = int(bytes[offset+1])
	l.Engine = int(bytes[offset+2])
	offset += 3
	var ok bool
	if l.Name, ok = text(bytes, &offset, NameSize); !ok {
		return nil, ErrMalformed
	}
	if l.Map, ok = text(bytes, &offset, MapSize); !ok {
		return nil, ErrMalformed
	}
	if l.Gametype, ok = text(bytes, &offset, GametypeSize); !ok {
		return nil, ErrMalformed
	}
	if offset+StampSize+SignatureSize != len(bytes) {
		return nil, ErrMalformed
	}
	copy(l.Stamp[:], bytes[offset:offset+StampSize])
	l.Kind = int(l.Stamp[0])
	offset += StampSize
	l.SignedSize = offset
	l.Signature = append([]byte(nil), bytes[offset:]...)
	return l, nil
}

// Verify checks the host's signature of a listing read from bytes.
func (l *Listing) Verify(bytes []byte) error {
	if sign.SmallOrder(l.Key) {
		return ErrKey
	}
	message := make([]byte, 0, len(SignatureLabel)+l.SignedSize)
	message = append(message, SignatureLabel...)
	message = append(message, bytes[:l.SignedSize]...)
	if !ed25519.Verify(l.Key, message, l.Signature) {
		return ErrSignature
	}
	return nil
}

// Read parses a listing and checks its signature.
func Read(bytes []byte) (*Listing, error) {
	l, err := Parse(bytes)
	if err != nil {
		return nil, err
	}
	if err := l.Verify(bytes); err != nil {
		return nil, err
	}
	return l, nil
}

// Fields are what Make writes.
type Fields struct {
	NetworkVersion int
	Flags          int
	Sequence       uint32
	Time           uint32
	Token          [TokenSize]byte
	// written in the token's place with FlagPassword (56 bytes)
	Sealed     []byte
	Players    int
	MaxPlayers int
	Engine     int
	Name       string
	Map        string
	Gametype   string
	Kind       int
}

func put(out []byte, value string, maximum int) []byte {
	if len(value) > maximum {
		value = value[:maximum]
	}
	out = append(out, byte(len(value)))
	return append(out, value...)
}

// Make writes and signs a listing as listing_make does (the tests' and the
// test vectors' listings).
func Make(host ed25519.PrivateKey, f Fields) []byte {
	out := []byte{'H', 'L', Format, byte(f.NetworkVersion >> 8), byte(f.NetworkVersion), byte(f.Flags)}
	out = binary.BigEndian.AppendUint32(out, f.Sequence)
	out = binary.BigEndian.AppendUint32(out, f.Time)
	out = append(out, host.Public().(ed25519.PublicKey)...)
	if f.Flags&FlagPassword != 0 {
		sealed := make([]byte, SealedSize)
		copy(sealed, f.Sealed)
		out = append(out, sealed...)
	} else {
		out = append(out, f.Token[:]...)
	}
	clamp := func(n int) byte {
		if n > 255 {
			return 255
		}
		if n < 0 {
			return 0
		}
		return byte(n)
	}
	out = append(out, clamp(f.Players), clamp(f.MaxPlayers), byte(f.Engine))
	out = put(out, f.Name, NameSize)
	out = put(out, f.Map, MapSize)
	out = put(out, f.Gametype, GametypeSize)
	stamp := make([]byte, StampSize)
	stamp[0] = byte(f.Kind)
	out = append(out, stamp...)
	message := append([]byte(SignatureLabel), out...)
	return append(out, ed25519.Sign(host, message)...)
}
