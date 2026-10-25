// Package probe proves that a published server's UDP port is reachable and
// that the publisher's key holder answers on it: the master sends
// "OPCE-PROBE" 0x01 master_key_id[8] nonce[16] (35 bytes) to the server's
// address and takes only "OPCE-PROBE-ACK" 0x01 master_key_id[8] nonce[16]
// signature[64] (103 bytes) from that address, the signature being the
// publisher key's of "probe" || master_key_id || nonce. Each probe round has
// a nonce of its own; the server answers a nonce once a second at most.
package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"time"
)

const (
	ProbeMagic   = "OPCE-PROBE"
	AckMagic     = "OPCE-PROBE-ACK"
	Version      = 1
	KeyIDSize    = 8
	NonceSize    = 16
	ProbeSize    = len(ProbeMagic) + 1 + KeyIDSize + NonceSize
	AckSize      = len(AckMagic) + 1 + KeyIDSize + NonceSize + ed25519.SignatureSize
	SignedPrefix = "probe"
)

// Probe writes a probe datagram.
func Probe(masterKeyID [KeyIDSize]byte, nonce [NonceSize]byte) []byte {
	out := make([]byte, 0, ProbeSize)
	out = append(out, ProbeMagic...)
	out = append(out, Version)
	out = append(out, masterKeyID[:]...)
	return append(out, nonce[:]...)
}

// SignedMessage is what an answer's signature covers.
func SignedMessage(masterKeyID [KeyIDSize]byte, nonce [NonceSize]byte) []byte {
	out := make([]byte, 0, len(SignedPrefix)+KeyIDSize+NonceSize)
	out = append(out, SignedPrefix...)
	out = append(out, masterKeyID[:]...)
	return append(out, nonce[:]...)
}

// Answer writes the answer a server sends (the reference publisher's and
// the tests').
func Answer(publisher ed25519.PrivateKey, masterKeyID [KeyIDSize]byte, nonce [NonceSize]byte) []byte {
	out := make([]byte, 0, AckSize)
	out = append(out, AckMagic...)
	out = append(out, Version)
	out = append(out, masterKeyID[:]...)
	out = append(out, nonce[:]...)
	return append(out, ed25519.Sign(publisher, SignedMessage(masterKeyID, nonce))...)
}

// ParseProbe reads a probe (what a server does).
func ParseProbe(packet []byte) (keyID [KeyIDSize]byte, nonce [NonceSize]byte, err error) {
	if len(packet) != ProbeSize || !bytes.HasPrefix(packet, []byte(ProbeMagic)) || packet[len(ProbeMagic)] != Version {
		return keyID, nonce, errors.New("not a probe")
	}
	offset := len(ProbeMagic) + 1
	copy(keyID[:], packet[offset:])
	copy(nonce[:], packet[offset+KeyIDSize:])
	return keyID, nonce, nil
}

// Ack is an answer read.
type Ack struct {
	MasterKeyID [KeyIDSize]byte
	Nonce       [NonceSize]byte
	Signature   []byte
}

// ParseAck reads an answer.
func ParseAck(packet []byte) (Ack, error) {
	var ack Ack
	if len(packet) != AckSize || !bytes.HasPrefix(packet, []byte(AckMagic)) || packet[len(AckMagic)] != Version {
		return ack, errors.New("not a probe answer")
	}
	offset := len(AckMagic) + 1
	copy(ack.MasterKeyID[:], packet[offset:])
	offset += KeyIDSize
	copy(ack.Nonce[:], packet[offset:])
	offset += NonceSize
	ack.Signature = append([]byte(nil), packet[offset:]...)
	return ack, nil
}

// Verify checks an answer's signature with the publisher's key.
func (a Ack) Verify(publisher ed25519.PublicKey) bool {
	return ed25519.Verify(publisher, SignedMessage(a.MasterKeyID, a.Nonce), a.Signature)
}

// NonceStep is the time step mixed into a probe's nonce: each probe round
// takes the nonce of the step it starts in, so each round has a new one
// (the prober starts rounds of one address and key at least a step apart).
const NonceStep = 30 * time.Second

// Step is the step a time falls in: Unix seconds / 30.
func Step(t time.Time) int64 { return t.Unix() / int64(NonceStep/time.Second) }

// Seeds derive the probes' nonces without keeping any: a nonce is the first
// 16 bytes of HMAC-SHA-256(seed, "opence-probe-1" 0 address 0 publisher key
// id 0 step), the step the round's decimal Step; the current and the
// previous hour's seeds, and the current and the previous step, are
// accepted.
type Seeds struct {
	mu       sync.Mutex
	period   time.Duration
	current  []byte
	previous []byte
	rotated  time.Time
}

// NewSeeds makes seeds that rotate each period (an hour in the master).
func NewSeeds(period time.Duration, now time.Time) *Seeds {
	s := &Seeds{period: period, rotated: now}
	s.current = randomSeed()
	s.previous = randomSeed()
	return s
}

func randomSeed() []byte {
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	return seed
}

// NewSeedsFixed makes seeds from given bytes (tests and test vectors).
func NewSeedsFixed(current, previous []byte, period time.Duration, now time.Time) *Seeds {
	return &Seeds{period: period, rotated: now, current: current, previous: previous}
}

func (s *Seeds) rotate(now time.Time) {
	for now.Sub(s.rotated) >= s.period {
		s.previous, s.current = s.current, randomSeed()
		s.rotated = s.rotated.Add(s.period)
	}
}

func derive(seed []byte, address, keyID string, step int64) [NonceSize]byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("opence-probe-1\x00" + address + "\x00" + keyID + "\x00" + strconv.FormatInt(step, 10)))
	var nonce [NonceSize]byte
	copy(nonce[:], mac.Sum(nil))
	return nonce
}

// Nonce is the nonce for a probe round of address for a publisher's key,
// started at now.
func (s *Seeds) Nonce(now time.Time, address, keyID string) [NonceSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotate(now)
	return derive(s.current, address, keyID, Step(now))
}

// Valid tells whether a nonce is one of the current or the previous seed's
// for address and key, in the current or the previous step.
func (s *Seeds) Valid(now time.Time, nonce [NonceSize]byte, address, keyID string) bool {
	s.mu.Lock()
	s.rotate(now)
	current, previous := s.current, s.previous
	s.mu.Unlock()
	step := Step(now)
	for _, seed := range [][]byte{current, previous} {
		for _, at := range []int64{step, step - 1} {
			expected := derive(seed, address, keyID, at)
			if hmac.Equal(expected[:], nonce[:]) {
				return true
			}
		}
	}
	return false
}
