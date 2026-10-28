package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// The player keys' links to Discord accounts, and the passes the master
// signs for them (docs/master_protocol.md, "Player keys, links and
// passes"). The web pages link (after Discord's OAuth2), the API gives the
// passes, the admin pages and the command line unlink and revoke.

var snowflake = regexp.MustCompile(`^[0-9]{17,20}$`)

// ValidDiscordID tells whether text is a Discord id (a snowflake).
func ValidDiscordID(text string) bool {
	if !snowflake.MatchString(text) {
		return false
	}
	_, err := strconv.ParseUint(text, 10, 64)
	return err == nil
}

// DiscordCreated is when a Discord account was made, in Unix milliseconds:
// its id's top 42 bits are milliseconds since 2015-01-01.
func DiscordCreated(id uint64) int64 {
	return int64(id>>22) + 1420070400000
}

// MaximumDiscordName is the longest Discord username kept.
const MaximumDiscordName = 64

// ErrNotLinked is a pass asked for a key no Discord account holds.
var ErrNotLinked = errors.New("no Discord account holds the key")

// RevokedError is a pass asked for (or a link made) by an account the
// master's admins revoked.
type RevokedError struct {
	Reason string
}

func (e *RevokedError) Error() string {
	if e.Reason == "" {
		return "the Discord account was revoked by the master's admins"
	}
	return "the Discord account was revoked by the master's admins: " + e.Reason
}

// Revoked returns an account's revocation (nil if it is not revoked).
func (m *Master) Revoked(discordID string) (*store.Revocation, error) {
	return m.Store.Revocation(discordID)
}

// SaveLink records a player key as a Discord account's (flags: the pass's,
// 1 for a member of the master's Discord server), and writes it to the
// audit log. A revoked account is refused; a key linked to another account
// is moved; past MASTER_LINK_MAX_KEYS the account's least recently used
// keys are dropped.
func (m *Master) SaveLink(public ed25519.PublicKey, discordID, name string, flags int, actor string) error {
	if len(public) != ed25519.PublicKeySize || sign.SmallOrder(public) {
		return refuse("schema", "the player key is not a usable Ed25519 key")
	}
	if !ValidDiscordID(discordID) {
		return refuse("schema", "a Discord id is 17 to 20 digits")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > MaximumDiscordName {
		return refuse("schema", "a Discord username is 1 to %d characters", MaximumDiscordName)
	}
	revoked, err := m.Store.Revocation(discordID)
	if err != nil {
		return err
	}
	if revoked != nil {
		return &RevokedError{Reason: revoked.Reason}
	}
	keyID := sign.KeyID(public)
	replaced, dropped, err := m.Store.SaveLink(store.Link{Key: hex.EncodeToString(public), KeyID: keyID,
		DiscordID: discordID, DiscordName: name, Created: m.now(), Flags: flags}, m.Config.LinkMaxKeys)
	if err != nil {
		return err
	}
	detail := "discord:" + discordID + " " + name
	if replaced != "" {
		detail += ", taken from discord:" + replaced
	}
	for _, d := range dropped {
		detail += ", dropped key " + d.KeyID
	}
	if flags&sign.PassFlagGuild != 0 {
		detail += ", in the Discord server"
	}
	_ = m.Store.Audit(actor, "link", keyID, detail)
	return nil
}

// Unlink deletes a key's link (keyHex: 64 hexadecimal digits); when
// discordID is set, only that account's.
func (m *Master) Unlink(keyHex, discordID, actor string) error {
	link, err := m.Store.LinkOf(keyHex)
	if errors.Is(err, store.ErrNotFound) || (err == nil && discordID != "" && link.DiscordID != discordID) {
		return refuse("not_found", "no such linked key")
	} else if err != nil {
		return err
	}
	if _, err := m.Store.DeleteLink(keyHex, discordID); err != nil {
		return err
	}
	_ = m.Store.Audit(actor, "unlink", link.KeyID, "discord:"+link.DiscordID)
	return nil
}

// UnlinkAccount deletes every link of an account, returning how many.
func (m *Master) UnlinkAccount(discordID, actor string) (int, error) {
	n, err := m.Store.DeleteAccountLinks(discordID)
	if err != nil {
		return 0, err
	}
	_ = m.Store.Audit(actor, "unlink-account", "discord:"+discordID, fmt.Sprintf("%d keys", n))
	return n, nil
}

// MaximumRevocationReason is the longest revocation reason, in bytes.
const MaximumRevocationReason = 300

// RevokeAccount revokes a Discord account: its links are deleted, a pass
// asked for one of its keys is refused with the reason, and it may not link
// again until the revocation is lifted.
func (m *Master) RevokeAccount(discordID, reason, actor string) (int, error) {
	if !ValidDiscordID(discordID) {
		return 0, refuse("schema", "a Discord id is 17 to 20 digits")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > MaximumRevocationReason || !Printable(reason) {
		return 0, refuse("schema", "a revocation needs a reason: 1 to %d printable characters", MaximumRevocationReason)
	}
	n, err := m.Store.Revoke(store.Revocation{DiscordID: discordID, Reason: reason, By: actor, At: m.now()})
	if err != nil {
		return 0, err
	}
	_ = m.Store.Audit(actor, "revoke-link", "discord:"+discordID, fmt.Sprintf("%s (%d keys unlinked)", reason, n))
	return n, nil
}

// LiftRevocation lets a revoked account link again.
func (m *Master) LiftRevocation(discordID, actor string) error {
	lifted, err := m.Store.LiftRevocation(discordID)
	if err != nil {
		return err
	}
	if !lifted {
		return refuse("not_found", "discord:%s is not revoked", discordID)
	}
	_ = m.Store.Audit(actor, "lift-revocation", "discord:"+discordID, "")
	return nil
}

// Pass makes a new pass for a player key: ErrNotLinked if no account holds
// it, a *RevokedError if its account was revoked.
func (m *Master) Pass(public ed25519.PublicKey) ([]byte, error) {
	key := hex.EncodeToString(public)
	link, err := m.Store.LinkOf(key)
	if errors.Is(err, store.ErrNotFound) {
		revoked, err := m.Store.KeyRevocation(key)
		if err != nil {
			return nil, err
		}
		if revoked != nil {
			return nil, &RevokedError{Reason: revoked.Reason}
		}
		return nil, ErrNotLinked
	} else if err != nil {
		return nil, err
	}
	if revoked, err := m.Store.Revocation(link.DiscordID); err != nil {
		return nil, err
	} else if revoked != nil {
		return nil, &RevokedError{Reason: revoked.Reason}
	}
	id, err := strconv.ParseUint(link.DiscordID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("link of key %s: a Discord id that is not one", link.KeyID)
	}
	now := m.now()
	pass := sign.MakePass(m.Key, sign.Pass{Flags: byte(link.Flags), MasterKeyID: m.KeyIDBytes, Player: public,
		DiscordID: id, DiscordName: link.DiscordName, Issued: now, Expires: now + int64(m.Config.PassTTL.Seconds())})
	if err := m.Store.TouchPass(key, now); err != nil {
		return nil, err
	}
	return pass, nil
}
