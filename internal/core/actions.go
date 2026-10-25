package core

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

// ActionError is a refusal with a protocol error code.
type ActionError struct {
	Code    string
	Message string
}

func (e *ActionError) Error() string { return e.Message }

func refuse(code, format string, args ...any) error {
	return &ActionError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Link is a path on the master's public URL (the path alone without one).
func (m *Master) Link(path string) string { return m.link(path) }

func (m *Master) link(path string) string {
	if m.Config.PublicURL == "" {
		return path
	}
	return m.Config.PublicURL + path
}

// KeyKnown tells whether a key belongs to a publisher already.
func (m *Master) KeyKnown(keyID string) (bool, error) {
	records, err := m.Store.KeyRecords(keyID)
	return len(records) > 0, err
}

// MaximumReason is the longest denial reason, in characters: the
// applicant's direct message, with it, fits Discord's 2000.
const MaximumReason = 300

// notPending refuses a decision on an application decided already (perhaps
// a moment before, by another approver).
func (m *Master) notPending(id string) error {
	a, err := m.Store.Application(id)
	if err != nil {
		return refuse("not_pending", "application %s is not pending", id)
	}
	if a.Status == model.ApplicationApproved {
		return refuse("already_approved", "application %s is approved already (publisher %s)", a.ID, a.PublisherID)
	}
	return refuse("not_pending", "application %s is %s", a.ID, a.Status)
}

// Approve approves a pending application: a publisher, this master's
// opinion and the key, active. The decision is made in one transaction
// that first takes the application from pending, so that of two decisions
// at once (two approvers, or Discord and the admin page) one is made and the
// other refused; a denied application is not approved.
func (m *Master) Approve(applicationID string, quota int, actor string) (*model.Publisher, error) {
	a, err := m.Store.Application(applicationID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse("not_found", "no application %s", applicationID)
	} else if err != nil {
		return nil, err
	}
	if a.Status != model.ApplicationPending {
		return nil, m.notPending(a.ID)
	}
	if quota == 0 {
		quota = m.Config.DefaultQuota
	}
	if quota < 1 || quota > MaximumQuota {
		return nil, refuse("schema", "a quota is 1 to %d", MaximumQuota)
	}
	now := m.now()
	p := &model.Publisher{ID: NewID("p_"), Name: a.Name, Email: a.Email, Discord: a.Discord, DiscordID: a.DiscordID,
		Origin: m.KeyID, Since: now, Created: now, Updated: now}
	o := model.Opinion{PublisherID: p.ID, Source: m.KeyID, Status: model.Approved, Quota: quota, Updated: now}
	k := model.KeyRecord{KeyID: a.KeyID, Source: m.KeyID, PublisherID: p.ID, PublicKey: a.PublicKey,
		Status: model.KeyActive, Updated: now}
	a.DecidedBy = actor
	switch err := m.Store.Approve(a, p, o, k); {
	case errors.Is(err, store.ErrNotPending):
		return nil, m.notPending(a.ID)
	case errors.Is(err, store.ErrKeyExists):
		return nil, refuse("key_exists", "key %s belongs to a publisher already", a.KeyID)
	case err != nil:
		return nil, err
	}
	_ = m.Store.Audit(actor, "approve", a.ID, fmt.Sprintf("publisher %s, key %s, quota %d", p.ID, a.KeyID, quota))
	m.changed(a.ID)
	if a.Email == "" {
		// (a Discord applicant is told by the bot)
		return p, nil
	}
	m.Notifier.Mail(a.Email, "Your OpenCE master application is approved",
		fmt.Sprintf("Hello %s,\n\nYour application %s to %s is approved: you are publisher %s, with up to %d "+
			"servers at once. A server publishing with key %s is listed at its next publish (within 30 seconds), "+
			"once its UDP port answers the master's probe. The masters share approvals: the other official "+
			"masters list it too.\n\n%s\n", a.Name, a.ID, m.Name(), p.ID, quota, a.KeyID, m.link("/")))
	return p, nil
}

// Deny refuses a pending application, with a reason the operator is told
// (MaximumReason characters at most), as atomically as Approve.
func (m *Master) Deny(applicationID, reason, actor string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return refuse("schema", "a denial needs a reason")
	}
	if utf8.RuneCountInString(reason) > MaximumReason {
		return refuse("schema", "a denial's reason is %d characters at most", MaximumReason)
	}
	a, err := m.Store.Application(applicationID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse("not_found", "no application %s", applicationID)
	} else if err != nil {
		return err
	}
	if a.Status != model.ApplicationPending {
		return m.notPending(a.ID)
	}
	if err := m.Store.Deny(a.ID, reason, actor); errors.Is(err, store.ErrNotPending) {
		return m.notPending(a.ID)
	} else if err != nil {
		return err
	}
	_ = m.Store.Audit(actor, "deny", a.ID, reason)
	m.changed(a.ID)
	if a.Email == "" {
		return nil
	}
	contact := ""
	if m.Contact() != "" {
		contact = "\nContact: " + m.Contact() + "\n"
	}
	m.Notifier.Mail(a.Email, "Your OpenCE master application",
		fmt.Sprintf("Hello %s,\n\nYour application %s to %s was not approved: %s\n%s", a.Name, a.ID,
			m.Name(), reason, contact))
	return nil
}

func (m *Master) ownOpinion(publisherID string) (*model.Opinion, []model.Opinion, error) {
	opinions, err := m.Store.Opinions(publisherID)
	if err != nil {
		return nil, nil, err
	}
	for i := range opinions {
		if opinions[i].Source == m.KeyID {
			return &opinions[i], opinions, nil
		}
	}
	return nil, opinions, nil
}

// SetStatus records this master's word on a publisher: suspended,
// approved (a resume) or revoked (for good).
func (m *Master) SetStatus(publisherID, status, reason, actor string) error {
	if !model.ValidStatus(status) {
		return refuse("schema", "status is approved, suspended or revoked")
	}
	if _, err := m.Store.Publisher(publisherID); errors.Is(err, store.ErrNotFound) {
		return refuse("not_found", "no publisher %s", publisherID)
	} else if err != nil {
		return err
	}
	own, opinions, err := m.ownOpinion(publisherID)
	if err != nil {
		return err
	}
	quota := 0
	if own != nil {
		if own.Status == model.Revoked && status != model.Revoked {
			return refuse("revoked", "publisher %s is revoked, which is permanent", publisherID)
		}
		quota = own.Quota
	} else {
		_, quota, _ = model.Effective(opinions, m.Trusted)
	}
	if err := m.Store.SetOpinion(model.Opinion{PublisherID: publisherID, Source: m.KeyID, Status: status,
		Quota: quota, Reason: reason, Updated: m.now()}); err != nil {
		return err
	}
	action := map[string]string{model.Approved: "resume", model.Suspended: "suspend", model.Revoked: "revoke"}[status]
	_ = m.Store.Audit(actor, action, publisherID, reason)
	m.InvalidateList()
	if state, err := m.State(publisherID); err == nil && state.Status != status {
		m.Log.Info("publisher's status set here, another master's is stricter", "publisher", publisherID,
			"here", status, "effective", state.Status, "by", state.StatusBy)
	}
	return nil
}

// SetQuota sets this master's quota for a publisher.
func (m *Master) SetQuota(publisherID string, quota int, actor string) error {
	if quota < 1 || quota > MaximumQuota {
		return refuse("schema", "a quota is 1 to %d", MaximumQuota)
	}
	own, opinions, err := m.ownOpinion(publisherID)
	if err != nil {
		return err
	}
	o := model.Opinion{PublisherID: publisherID, Source: m.KeyID, Quota: quota, Updated: m.now()}
	if own != nil {
		o.Status, o.Reason = own.Status, own.Reason
	} else {
		if o.Status, _, _ = model.Effective(opinions, m.Trusted); o.Status == "" {
			return refuse("not_found", "no publisher %s", publisherID)
		}
	}
	if err := m.Store.SetOpinion(o); err != nil {
		return err
	}
	return m.Store.Audit(actor, "quota", publisherID, fmt.Sprint(quota))
}

// RevokeKey revokes a key for good.
func (m *Master) RevokeKey(keyID, reason, actor string) error {
	records, err := m.Store.KeyRecords(keyID)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return refuse("not_found", "no key %s", keyID)
	}
	r := records[0]
	for _, other := range records {
		if other.Source == m.KeyID {
			r = other
		}
	}
	r.Source, r.Status, r.Updated = m.KeyID, model.KeyRevoked, m.now()
	if err := m.Store.SetKey(r); err != nil {
		return err
	}
	m.InvalidateList()
	return m.Store.Audit(actor, "revoke-key", keyID, fmt.Sprintf("publisher %s: %s", r.PublisherID, reason))
}

// AddKey adds a key to a publisher (a publisher's POST /v1/keys).
func (m *Master) AddKey(publisherID string, public ed25519.PublicKey, actor string) (string, error) {
	keyID := sign.KeyID(public)
	if known, err := m.KeyKnown(keyID); err != nil {
		return "", err
	} else if known {
		return "", refuse("key_exists", "key %s is known already", keyID)
	}
	state, err := m.State(publisherID)
	if err != nil {
		return "", err
	}
	active := 0
	for _, k := range state.Keys {
		if k.Status == model.KeyActive {
			active++
		}
	}
	if active >= MaximumKeys {
		return "", refuse("too_many_keys", "a publisher holds at most %d active keys", MaximumKeys)
	}
	if err := m.Store.SetKey(model.KeyRecord{KeyID: keyID, Source: m.KeyID, PublisherID: publisherID,
		PublicKey: sign.PublicKeyText(public), Status: model.KeyActive, Updated: m.now()}); err != nil {
		return "", err
	}
	_ = m.Store.Audit(actor, "add-key", publisherID, keyID)
	return keyID, nil
}

// SetServerFlags sets a server's hidden and trusted flags.
func (m *Master) SetServerFlags(serverID string, hidden bool, reason string, trusted bool, actor string) error {
	if err := m.Store.SetServerFlags(serverID, hidden, reason, trusted); errors.Is(err, store.ErrNotFound) {
		return refuse("not_found", "no server %s", serverID)
	} else if err != nil {
		return err
	}
	m.InvalidateList()
	return m.Store.Audit(actor, "server-flags", serverID, fmt.Sprintf("hidden=%v trusted=%v %s", hidden, trusted, reason))
}
