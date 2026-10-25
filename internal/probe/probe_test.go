package probe

import (
	"crypto/ed25519"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestPackets(t *testing.T) {
	var id [KeyIDSize]byte
	var nonce [NonceSize]byte
	copy(id[:], "masterid")
	copy(nonce[:], "0123456789abcdef")
	packet := Probe(id, nonce)
	if len(packet) != 35 || string(packet[:10]) != "OPCE-PROBE" || packet[10] != 1 {
		t.Fatalf("probe %x", packet)
	}
	gotID, gotNonce, err := ParseProbe(packet)
	if err != nil || gotID != id || gotNonce != nonce {
		t.Fatal("probe does not read back")
	}
	_, publisher, _ := ed25519.GenerateKey(nil)
	answer := Answer(publisher, id, nonce)
	if len(answer) != 103 || string(answer[:14]) != "OPCE-PROBE-ACK" || answer[14] != 1 {
		t.Fatalf("answer %x", answer)
	}
	ack, err := ParseAck(answer)
	if err != nil || ack.MasterKeyID != id || ack.Nonce != nonce || !ack.Verify(publisher.Public().(ed25519.PublicKey)) {
		t.Fatal("answer does not read back")
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if ack.Verify(other.Public().(ed25519.PublicKey)) {
		t.Fatal("answer verifies with another key")
	}
	for _, bad := range [][]byte{answer[:102], append(answer, 0), append([]byte("OPCE-PROBE-ACK\x02"), answer[15:]...)} {
		if _, err := ParseAck(bad); err == nil {
			t.Fatalf("bad answer read: %x", bad)
		}
	}
	if string(SignedMessage(id, nonce)) != "probe"+"masterid"+"0123456789abcdef" {
		t.Fatal("signed message")
	}
}

func TestStatelessNonces(t *testing.T) {
	c := &clock{now: time.Unix(1760900010, 0)}
	seeds := NewSeeds(time.Hour, c.Now())
	nonce := seeds.Nonce(c.Now(), "203.0.113.5:2302", "0123456789abcdef")
	if !seeds.Valid(c.Now(), nonce, "203.0.113.5:2302", "0123456789abcdef") {
		t.Fatal("own nonce refused")
	}
	if seeds.Valid(c.Now(), nonce, "203.0.113.6:2302", "0123456789abcdef") ||
		seeds.Valid(c.Now(), nonce, "203.0.113.5:2302", "fedcba9876543210") {
		t.Fatal("nonce valid for another address or key")
	}
	// the same step, the same nonce; the next step, another
	if seeds.Nonce(c.Now().Add(29*time.Second), "203.0.113.5:2302", "0123456789abcdef") != nonce {
		t.Fatal("two nonces in one step")
	}
	next := seeds.Nonce(c.Now().Add(30*time.Second), "203.0.113.5:2302", "0123456789abcdef")
	if next == nonce {
		t.Fatal("the next step's nonce is the same")
	}
	// a round's answer is taken in the next step, not after
	c.Add(59 * time.Second)
	if !seeds.Valid(c.Now(), nonce, "203.0.113.5:2302", "0123456789abcdef") {
		t.Fatal("the previous step's nonce refused")
	}
	c.Add(NonceStep)
	if seeds.Valid(c.Now(), nonce, "203.0.113.5:2302", "0123456789abcdef") {
		t.Fatal("a nonce two steps old accepted")
	}
	// the previous hour's seed is still accepted, not the one before
	at := c.Now()
	nonce = seeds.Nonce(at, "203.0.113.5:2302", "0123456789abcdef")
	other := NewSeedsFixed(seeds.current, seeds.previous, time.Hour, seeds.rotated)
	other.rotate(at.Add(time.Hour))
	if !other.Valid(at, nonce, "203.0.113.5:2302", "0123456789abcdef") {
		t.Fatal("previous seed's nonce refused")
	}
	other.rotate(at.Add(2 * time.Hour))
	if other.Valid(at, nonce, "203.0.113.5:2302", "0123456789abcdef") {
		t.Fatal("a nonce two seeds old accepted")
	}
}

// Each round of a target has its own nonce, the same for its attempts.
func TestRoundNonces(t *testing.T) {
	c := &clock{now: time.Unix(1760900000, 0)}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer conn.Close()
	var masterID [KeyIDSize]byte
	p := New(conn, masterID, NewSeeds(time.Hour, c.Now()), c.Now, nil)
	_, publisher, _ := ed25519.GenerateKey(nil)
	address := Canonical(netip.MustParseAddrPort(server.LocalAddr().String()))
	read := func() [NonceSize]byte {
		buffer := make([]byte, 64)
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := server.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		_, nonce, err := ParseProbe(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		return nonce
	}
	key := publisher.Public().(ed25519.PublicKey)
	p.Touch("s1", address, "0123456789abcdef", key, nil)
	p.Tick()
	first := read()
	c.Add(Spacing)
	p.Tick()
	if read() != first {
		t.Fatal("a round's attempts differ")
	}
	// the server goes and comes back at once: its next round waits for
	// the next step, and has a new nonce
	p.Remove("s1")
	p.Touch("s1", address, "0123456789abcdef", key, nil)
	p.Tick()
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := server.ReadFromUDPAddrPort(make([]byte, 64)); err == nil {
		t.Fatal("a second round in one step")
	}
	c.Add(NonceStep)
	p.Tick()
	if read() == first {
		t.Fatal("two rounds share a nonce")
	}
}

// A dual-stack socket probes an IPv4 server.
func TestDualStack(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skip("no IPv6:", err)
	}
	defer conn.Close()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var masterID [KeyIDSize]byte
	copy(masterID[:], "M1234567")
	p := New(conn, masterID, NewSeeds(time.Hour, time.Now()), time.Now, nil)
	results := make(chan Result, 1)
	p.OnResult = func(r Result) { results <- r }
	_, publisher, _ := ed25519.GenerateKey(nil)
	go func() {
		buffer := make([]byte, 64)
		for {
			n, from, err := server.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if id, nonce, err := ParseProbe(buffer[:n]); err == nil {
				server.WriteToUDPAddrPort(Answer(publisher, id, nonce), from)
			}
		}
	}()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			p.Receive(buffer[:n], from)
		}
	}()
	address := Canonical(netip.MustParseAddrPort(server.LocalAddr().String()))
	p.Touch("s1", address, "0123456789abcdef", publisher.Public().(ed25519.PublicKey), nil)
	p.Tick()
	select {
	case r := <-results:
		if r.State != OK {
			t.Fatalf("result %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no answer through the dual-stack socket")
	}
}

func TestStateMachine(t *testing.T) {
	c := &clock{now: time.Unix(1760900000, 0)}
	target := &Target{State: Pending}
	target.Start(c.Now())
	sends := 0
	for i := 0; i < 80; i++ {
		send, failed := target.Step(c.Now())
		if send {
			sends++
		}
		if failed {
			break
		}
		c.Add(100 * time.Millisecond)
	}
	if sends != Attempts || target.State != Failed || target.InFlight() {
		t.Fatalf("sends %d, state %s", sends, target.State)
	}
	// a failed server is tried again a minute on, at a publish
	if target.Due(c.Now()) {
		t.Fatal("due at once after a failure")
	}
	c.Add(RetryFailed)
	if !target.Due(c.Now()) {
		t.Fatal("not due a minute after a failure")
	}
	target.Start(c.Now())
	target.Step(c.Now())
	target.Answered(c.Now())
	if target.State != OK || target.InFlight() || target.Due(c.Now()) {
		t.Fatal("answer not taken")
	}
	c.Add(Refresh)
	if !target.Due(c.Now()) {
		t.Fatal("not probed again after five minutes")
	}
	// a probe again keeps the server reachable until it fails
	target.Start(c.Now())
	if target.State != OK {
		t.Fatal("a probe again unlisted the server")
	}
}

func TestProberOverUDP(t *testing.T) {
	masterConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	_, publisher, _ := ed25519.GenerateKey(nil)
	_, impostor, _ := ed25519.GenerateKey(nil)
	var masterID [KeyIDSize]byte
	copy(masterID[:], "M1234567")
	seeds := NewSeeds(time.Hour, time.Now())
	p := New(masterConn, masterID, seeds, time.Now, nil)
	results := make(chan Result, 4)
	p.OnResult = func(r Result) { results <- r }
	go func() {
		buffer := make([]byte, 64)
		for {
			n, from, err := serverConn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			id, nonce, err := ParseProbe(buffer[:n])
			if err != nil {
				continue
			}
			// a wrong key's answer first, then the right one
			serverConn.WriteToUDPAddrPort(Answer(impostor, id, nonce), from)
			serverConn.WriteToUDPAddrPort(Answer(publisher, id, nonce), from)
		}
	}()
	stop := make(chan struct{})
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := masterConn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			p.Receive(buffer[:n], from)
		}
	}()
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				p.Tick()
			}
		}
	}()
	defer close(stop)
	defer masterConn.Close()
	address := Canonical(netip.MustParseAddrPort(serverConn.LocalAddr().String()))
	if state := p.Touch("s1", address, "0123456789abcdef", publisher.Public().(ed25519.PublicKey), nil); state != Pending {
		t.Fatalf("first state %s", state)
	}
	select {
	case r := <-results:
		if r.State != OK || r.ServerID != "s1" {
			t.Fatalf("result %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no answer taken")
	}
	if state, _ := p.StateOf("s1"); state != OK {
		t.Fatalf("state %s", state)
	}
	// an unanswered address fails after three attempts
	silent, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	silentAddress := silent.LocalAddr().String()
	silent.Close()
	p.Touch("s2", silentAddress, "0123456789abcdef", publisher.Public().(ed25519.PublicKey), nil)
	select {
	case r := <-results:
		if r.State != Failed || r.ServerID != "s2" {
			t.Fatalf("result %+v", r)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no failure")
	}
}
