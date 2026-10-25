package probe

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// State is a server's probe state.
type State string

const (
	// no answer yet to a probe of this address
	Pending State = "pending"
	OK      State = "ok"
	// three attempts unanswered
	Failed State = "failed"
)

const (
	Attempts = 3
	Spacing  = 2 * time.Second
	// a reachable server is probed again this often
	Refresh = 5 * time.Minute
	// an unreachable one at its first publish after this
	RetryFailed = time.Minute
	// a target not touched by a publish for this long is forgotten
	Forget = 10 * time.Minute
)

// Target is one server's probe: the state machine the prober steps.
type Target struct {
	ServerID string
	Address  string
	KeyID    string
	Key      ed25519.PublicKey
	State    State
	LastOK   time.Time
	Touched  time.Time

	inFlight  bool
	attempts  int
	nextSend  time.Time
	nextProbe time.Time
	started   time.Time
	// the round's nonce, made at its first attempt
	nonce [NonceSize]byte
}

// Start begins a round of attempts.
func (t *Target) Start(now time.Time) {
	t.inFlight = true
	t.attempts = 0
	t.nextSend = now
	t.started = now
}

// Due tells whether a new round should start.
func (t *Target) Due(now time.Time) bool {
	return !t.inFlight && !now.Before(t.nextProbe)
}

// InFlight tells whether a round is under way.
func (t *Target) InFlight() bool { return t.inFlight }

// Step advances a round: whether to send an attempt now, and whether the
// round has just failed.
func (t *Target) Step(now time.Time) (send, failed bool) {
	if !t.inFlight || now.Before(t.nextSend) {
		return false, false
	}
	if t.attempts < Attempts {
		t.attempts++
		t.nextSend = now.Add(Spacing)
		return true, false
	}
	t.inFlight = false
	t.State = Failed
	t.nextProbe = now.Add(RetryFailed)
	return false, true
}

// Answered ends a round with a valid answer.
func (t *Target) Answered(now time.Time) {
	t.inFlight = false
	t.State = OK
	t.LastOK = now
	t.nextProbe = now.Add(Refresh)
}

// Result is a round's end.
type Result struct {
	ServerID string
	Address  string
	State    State
	At       time.Time
	RTT      time.Duration
}

// Known is what the database remembers of an earlier probe.
type Known struct {
	Address  string
	State    State
	ProbedAt time.Time
}

// Prober sends probes from one UDP socket and takes their answers.
type Prober struct {
	conn        *net.UDPConn
	masterKeyID [KeyIDSize]byte
	seeds       *Seeds
	now         func() time.Time
	log         *slog.Logger

	mu        sync.Mutex
	targets   map[string]*Target
	byAddress map[string]map[string]*Target
	// the step of the last round of each address and key, so that two
	// rounds never share a nonce
	rounds    map[string]int64
	roundStep int64

	OnResult func(Result)
	OnSend   func()

	ipv4Only bool
}

// New makes a prober on a bound socket (an IPv4 one, or a dual-stack IPv6
// one, which reaches IPv4 servers by their IPv4-mapped addresses).
func New(conn *net.UDPConn, masterKeyID [KeyIDSize]byte, seeds *Seeds, now func() time.Time, log *slog.Logger) *Prober {
	ipv4Only := false
	if local, ok := conn.LocalAddr().(*net.UDPAddr); ok && local.IP.To4() != nil {
		ipv4Only = true
	}
	return &Prober{ipv4Only: ipv4Only,
		conn: conn, masterKeyID: masterKeyID, seeds: seeds, now: now, log: log,
		targets: map[string]*Target{}, byAddress: map[string]map[string]*Target{}, rounds: map[string]int64{},
	}
}

// Canonical writes an address as the prober keys it (an IPv4-mapped IPv6
// address as IPv4).
func Canonical(address netip.AddrPort) string {
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port()).String()
}

func (p *Prober) unlink(t *Target) {
	if set := p.byAddress[t.Address]; set != nil {
		delete(set, t.ServerID)
		if len(set) == 0 {
			delete(p.byAddress, t.Address)
		}
	}
}

// Touch is called at each publish: it starts a probe of a new address or
// key, or one that is due, and returns the server's state.
func (p *Prober) Touch(serverID, address, keyID string, key ed25519.PublicKey, known *Known) State {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.targets[serverID]
	if t != nil && (t.Address != address || t.KeyID != keyID) {
		p.unlink(t)
		t = nil
	}
	if t == nil {
		t = &Target{ServerID: serverID, Address: address, KeyID: keyID, Key: key, State: Pending}
		if known != nil && known.Address == address && known.State == OK && now.Sub(known.ProbedAt) < Refresh {
			t.State = OK
			t.LastOK = known.ProbedAt
			t.nextProbe = known.ProbedAt.Add(Refresh)
		} else {
			t.Start(now)
		}
		p.targets[serverID] = t
		if p.byAddress[address] == nil {
			p.byAddress[address] = map[string]*Target{}
		}
		p.byAddress[address][serverID] = t
	} else if t.Due(now) {
		t.Start(now)
	}
	t.Touched = now
	return t.State
}

// Remove forgets a server (closed or deleted).
func (p *Prober) Remove(serverID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.targets[serverID]; t != nil {
		p.unlink(t)
		delete(p.targets, serverID)
	}
}

// StateOf is a server's state, and whether the prober knows it.
func (p *Prober) StateOf(serverID string) (State, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.targets[serverID]; t != nil {
		return t.State, true
	}
	return "", false
}

// Tick steps every target: the attempts to send, the rounds that failed.
func (p *Prober) Tick() {
	now := p.now()
	type send struct {
		to    netip.AddrPort
		nonce [NonceSize]byte
	}
	var sends []send
	var results []Result
	step := Step(now)
	p.mu.Lock()
	if step != p.roundStep {
		p.roundStep = step
		for key, at := range p.rounds {
			if at < step-1 {
				delete(p.rounds, key)
			}
		}
	}
	for id, t := range p.targets {
		if !t.inFlight && now.Sub(t.Touched) > Forget {
			p.unlink(t)
			delete(p.targets, id)
			continue
		}
		round := t.Address + "\x00" + t.KeyID
		if t.inFlight && t.attempts == 0 && !now.Before(t.nextSend) {
			if last, seen := p.rounds[round]; seen && last == step {
				// (a round of this address and key began in this step: the
				// next begins with the next step, and a new nonce)
				t.nextSend = time.Unix((step+1)*int64(NonceStep/time.Second), 0)
				continue
			}
		}
		do, failed := t.Step(now)
		if do {
			if t.attempts == 1 {
				t.nonce = p.seeds.Nonce(now, t.Address, t.KeyID)
				p.rounds[round] = step
			}
			to, err := netip.ParseAddrPort(t.Address)
			if err == nil {
				sends = append(sends, send{to, t.nonce})
			}
		}
		if failed {
			results = append(results, Result{ServerID: t.ServerID, Address: t.Address, State: Failed, At: now})
		}
	}
	p.mu.Unlock()
	for _, s := range sends {
		packet := Probe(p.masterKeyID, s.nonce)
		if p.ipv4Only && !s.to.Addr().Is4() {
			if p.log != nil {
				p.log.Debug("probe: an IPv6 address and an IPv4 socket", "to", s.to)
			}
		} else if _, err := p.conn.WriteToUDPAddrPort(packet, s.to); err != nil && p.log != nil {
			p.log.Debug("probe: send failed", "err", err)
		}
		if p.OnSend != nil {
			p.OnSend()
		}
	}
	for _, r := range results {
		if p.OnResult != nil {
			p.OnResult(r)
		}
	}
}

// Receive handles one datagram from an address.
func (p *Prober) Receive(packet []byte, from netip.AddrPort) {
	ack, err := ParseAck(packet)
	if err != nil || ack.MasterKeyID != p.masterKeyID {
		return
	}
	address := Canonical(from)
	now := p.now()
	var results []Result
	p.mu.Lock()
	for _, t := range p.byAddress[address] {
		if !t.inFlight || !p.seeds.Valid(now, ack.Nonce, address, t.KeyID) || !ack.Verify(t.Key) {
			continue
		}
		rtt := now.Sub(t.started)
		t.Answered(now)
		results = append(results, Result{ServerID: t.ServerID, Address: address, State: OK, At: now, RTT: rtt})
	}
	p.mu.Unlock()
	for _, r := range results {
		if p.OnResult != nil {
			p.OnResult(r)
		}
	}
}

// Run reads answers and steps the targets until the context ends.
func (p *Prober) Run(ctx context.Context) {
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := p.conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			p.Receive(buffer[:n], from)
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.conn.Close()
			return
		case <-ticker.C:
			p.Tick()
		}
	}
}
