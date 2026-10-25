package core

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// ApplicationInput is an application: what an operator sends the master's
// Discord bot (or an operator types on the command line).
type ApplicationInput struct {
	Name      string
	PublicKey string
	Servers   int
	Region    string
	Note      string
	Proof     *Proof
	// the applicant's Discord user id and username (none for the command
	// line's)
	DiscordID   string
	DiscordName string
}

// Proof is a proof of key: the publisher key's signature of a nonce the
// master gave.
type Proof struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// ProofLifetime is how long a proof's nonce is good for.
const ProofLifetime = 24 * time.Hour

var (
	discordIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	regionPattern    = regexp.MustCompile(`^[a-z0-9-]{0,16}$`)
	proofPattern     = regexp.MustCompile(`^opence-apply-([0-9]{1,19})-([0-9a-f]{16})$`)
)

// Printable tells whether text is printable ASCII.
func Printable(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] >= 0x7f {
			return false
		}
	}
	return true
}

func (m *Master) proofMAC(ts, binding string) string {
	secret := hmac.New(sha256.New, m.Key.Seed())
	secret.Write([]byte("opence-apply-proof"))
	mac := hmac.New(sha256.New, secret.Sum(nil))
	mac.Write([]byte(ts))
	if binding != "" {
		mac.Write([]byte{0})
		mac.Write([]byte(binding))
	}
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// ProofNonce is a nonce for a proof of key: "opence-apply-<unix>-<16 hex>",
// which the master recognises for ProofLifetime without keeping it. A nonce
// bound to a Discord user id (the bot's) is good for that user's
// applications only; one bound to nothing (the command line's) for an
// application of no Discord user.
func (m *Master) ProofNonce(binding string) string {
	ts := strconv.FormatInt(m.now(), 10)
	return "opence-apply-" + ts + "-" + m.proofMAC(ts, binding)
}

// CheckProof verifies a proof of key: the nonce is this master's for the
// binding, and fresh, and the signature (hexadecimal, as
// halo --server --sign prints it, or base64) is the key's of the nonce's
// text.
func (m *Master) CheckProof(public ed25519.PublicKey, p *Proof, binding string) error {
	match := proofPattern.FindStringSubmatch(strings.TrimSpace(p.Nonce))
	if match == nil || !hmac.Equal([]byte(match[2]), []byte(m.proofMAC(match[1], binding))) {
		return errors.New("the nonce is not one this master gave you")
	}
	ts, _ := strconv.ParseInt(match[1], 10, 64)
	if age := m.now() - ts; age < -60 || age > int64(ProofLifetime/time.Second) {
		return errors.New("the nonce has expired; ask for a new one")
	}
	text := strings.TrimSpace(p.Signature)
	signature, err := hex.DecodeString(text)
	if err != nil {
		signature, err = base64.StdEncoding.DecodeString(text)
	}
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("the signature is 128 hexadecimal digits")
	}
	if !ed25519.Verify(public, []byte(match[0]), signature) {
		return errors.New("the signature is not the key's of the nonce")
	}
	return nil
}

// FieldError is an input refused, naming its field.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

// LimitError is an application refused by a limit, to be tried again after
// Wait.
type LimitError struct {
	Message string
	Wait    time.Duration
}

func (e *LimitError) Error() string { return e.Message }

// checkUser refuses a Discord user's application past their limits, before
// its fields are read: one pending at a time, and MASTER_APPLICATIONS_PER_DAY
// a day.
func (m *Master) checkUser(discordID string) error {
	if pending, err := m.Store.PendingApplicationOfDiscord(discordID); err == nil {
		return refuse("duplicate", "your application %s is pending: wait for its decision", pending.ID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	n, err := m.Store.ApplicationsOfDiscord(discordID, m.now()-86400)
	if err != nil {
		return err
	}
	if n >= m.Config.ApplicationsPerDay {
		return &LimitError{Message: "too many applications from you today", Wait: 24 * time.Hour}
	}
	return nil
}

// checkLimits refuses an application past a limit once its fields are read:
// MASTER_APPLICATIONS_PER_KEY a day for a key, and, for an application
// without a proof of key, MASTER_APPLICATIONS_PER_HOUR such applications an
// hour in all (one with a proof is not refused for the hour's number: past
// it the admins are alerted, in Apply).
func (m *Master) checkLimits(keyID string, unproven bool) error {
	now := m.now()
	n, err := m.Store.ApplicationsForKey(keyID, now-86400)
	if err != nil {
		return err
	}
	if n >= m.Config.ApplicationsPerKey {
		return &LimitError{Message: "too many applications for this key today", Wait: 24 * time.Hour}
	}
	if unproven {
		n, err := m.Store.UnprovenApplicationsSince(now - 3600)
		if err != nil {
			return err
		}
		if n >= m.Config.ApplicationsPerHour {
			return &LimitError{Message: "this master takes no more applications without a proof of key this " +
				"hour; send one with a proof, or try again later", Wait: time.Hour}
		}
	}
	return nil
}

// Apply stores an application, from a Discord user (the bot's) or from the
// command line (none), and tells the admins; actor is the audit log's. The
// applications are taken one at a time, so that a user's or a key's sent at
// once do not each pass the limits that the others' storing would break.
func (m *Master) Apply(in ApplicationInput, actor string) (*model.Application, error) {
	m.applying.Lock()
	a, recent, err := m.apply(in, actor)
	m.applying.Unlock()
	if err != nil {
		return nil, err
	}
	m.announce(a, a.LogQueued, recent+1)
	m.changed(a.ID)
	return a, nil
}

// apply checks and stores an application, returning it and the number of
// applications in the hour before it.
func (m *Master) apply(in ApplicationInput, actor string) (*model.Application, int, error) {
	in.DiscordID = strings.TrimSpace(in.DiscordID)
	in.DiscordName = strings.TrimSpace(in.DiscordName)
	if in.DiscordID != "" {
		if !discordIDPattern.MatchString(in.DiscordID) {
			return nil, 0, &FieldError{"discord_id", "a Discord user id"}
		}
		if err := m.checkUser(in.DiscordID); err != nil {
			return nil, 0, err
		}
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Region = strings.ToLower(strings.TrimSpace(in.Region))
	switch {
	case len(in.DiscordName) > 37 || !Printable(in.DiscordName):
		return nil, 0, &FieldError{"discord", "up to 37 printable ASCII characters"}
	case len(in.Name) < 3 || len(in.Name) > 32 || !Printable(in.Name):
		return nil, 0, &FieldError{"name", "3 to 32 printable ASCII characters"}
	case in.Servers < 1 || in.Servers > 64:
		return nil, 0, &FieldError{"servers", "1 to 64"}
	case !regionPattern.MatchString(in.Region):
		return nil, 0, &FieldError{"region", "up to 16 of a-z, 0-9 and -"}
	case len(in.Note) > 1000:
		return nil, 0, &FieldError{"note", "1000 characters at most"}
	}
	public, err := sign.ParsePublicKey(strings.TrimSpace(in.PublicKey))
	if err != nil {
		return nil, 0, &FieldError{"public_key", err.Error()}
	}
	note := strings.Map(func(r rune) rune {
		if r == '\n' || (r >= 0x20 && r < 0x7f) {
			return r
		}
		return '?'
	}, strings.ReplaceAll(in.Note, "\r", ""))
	proofOK := false
	if in.Proof != nil && (strings.TrimSpace(in.Proof.Nonce) != "" || strings.TrimSpace(in.Proof.Signature) != "") {
		if err := m.CheckProof(public, in.Proof, in.DiscordID); err != nil {
			return nil, 0, &FieldError{"proof", err.Error()}
		}
		proofOK = true
	} else if m.Config.RequireProof {
		return nil, 0, &FieldError{"proof", "this master asks for a proof of key"}
	}
	keyID := sign.KeyID(public)
	if known, err := m.KeyKnown(keyID); err != nil {
		return nil, 0, err
	} else if known {
		return nil, 0, refuse("key_exists", "key %s belongs to a publisher already", keyID)
	}
	if err := m.checkLimits(keyID, !proofOK); err != nil {
		return nil, 0, err
	}
	if latest, err := m.Store.LatestApplicationForKey(keyID); err == nil && latest.Status == model.ApplicationPending {
		return nil, 0, refuse("duplicate", "application %s for key %s is pending", latest.ID, keyID)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, 0, err
	}
	now := m.now()
	recent, err := m.Store.ApplicationsSince(now - 3600)
	if err != nil {
		return nil, 0, err
	}
	// (past the hour's number, an application is not announced one by one)
	announced := m.Config.ApplicationsPerHour <= 0 || recent < m.Config.ApplicationsPerHour
	a := &model.Application{
		ID: NewID("a_"), Name: in.Name, Discord: in.DiscordName, DiscordID: in.DiscordID,
		PublicKey: sign.PublicKeyText(public), KeyID: keyID, Servers: in.Servers, Region: in.Region, Note: note,
		ProofOK: proofOK, Status: model.ApplicationPending, Created: now, Updated: now, LogQueued: announced,
		ToldStatus: model.ApplicationPending,
	}
	if err := m.Store.CreateApplication(a); err != nil {
		return nil, 0, err
	}
	_ = m.Store.Audit(actor, "apply", a.ID, fmt.Sprintf("key %s, %d servers", keyID, in.Servers))
	return a, recent, nil
}

// announce tells the admins of an application (the webhook, and the bot's
// log channel through the queue). Past MASTER_APPLICATIONS_PER_HOUR
// applications in the last hour (with a proof of key or without), they are
// alerted once, and the next ones that hour are logged, not announced one by
// one.
func (m *Master) announce(a *model.Application, announced bool, recent int) {
	if !announced {
		m.Log.Info("application not announced: past the hour's number", "id", a.ID, "key_id", a.KeyID)
		return
	}
	proofText := "with a proof of key"
	if !a.ProofOK {
		proofText = "WITHOUT a proof of key (anyone may have sent this key)"
	}
	m.Notifier.Notify(fmt.Sprintf("New application %s on %s: %q, key %s, %d servers, %s. Review: %s",
		a.ID, m.Name(), a.Name, a.KeyID, a.Servers, proofText, m.link("/admin/applications/"+a.ID)))
	if recent == m.Config.ApplicationsPerHour {
		m.Log.Warn("applications: the hour's number reached", "applications", recent)
		text := fmt.Sprintf("%d applications on %s in the last hour (MASTER_APPLICATIONS_PER_HOUR): "+
			"more than usual, perhaps a flood. The next ones this hour are taken but not announced here (those "+
			"without a proof of key are refused once as many of them came in an hour). Review: %s", recent,
			m.Name(), m.link("/admin/applications"))
		m.Notifier.Notify(text)
		if m.Watcher != nil {
			m.Watcher.Alert(text)
		}
	}
}
