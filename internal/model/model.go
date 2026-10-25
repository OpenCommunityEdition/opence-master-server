// Package model holds the records the master keeps and the rules that
// combine what several masters say of a publisher: each master's latest
// word (an opinion) is kept apart, and the most restrictive of the trusted
// masters' opinions is the publisher's status.
package model

import "time"

// Publisher statuses, from the least restrictive.
const (
	Approved  = "approved"
	Suspended = "suspended"
	Revoked   = "revoked"
	// not a stored status: an application waiting for review
	Pending = "pending"
)

// Key statuses.
const (
	KeyActive  = "active"
	KeyRevoked = "revoked"
)

// Application statuses.
const (
	ApplicationPending  = "pending"
	ApplicationApproved = "approved"
	ApplicationDenied   = "denied"
)

// Severity orders the publisher statuses; 0 for an unknown one.
func Severity(status string) int {
	switch status {
	case Approved:
		return 1
	case Suspended:
		return 2
	case Revoked:
		return 3
	}
	return 0
}

// ValidStatus tells whether a status may be stored.
func ValidStatus(status string) bool { return Severity(status) > 0 }

// Opinion is one master's word on a publisher.
type Opinion struct {
	PublisherID string `json:"-"`
	// the master's key id
	Source  string `json:"source"`
	Status  string `json:"status"`
	Quota   int    `json:"quota"`
	Reason  string `json:"reason,omitempty"`
	Updated int64  `json:"updated"`
}

// KeyRecord is one master's word on a publisher key.
type KeyRecord struct {
	KeyID       string `json:"key_id"`
	Source      string `json:"source"`
	PublisherID string `json:"publisher_id"`
	PublicKey   string `json:"public_key"`
	Status      string `json:"status"`
	Updated     int64  `json:"updated"`
}

// Publisher is a publisher's record.
type Publisher struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email,omitempty"`
	Discord string `json:"discord,omitempty"`
	// the master that approved it
	Origin  string `json:"origin"`
	Since   int64  `json:"since"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
}

// Effective is a publisher's status and quota from the opinions of the
// trusted sources: the most restrictive status, and the smallest quota
// given. An empty status means no trusted source knows it.
func Effective(opinions []Opinion, trusted func(source string) bool) (status string, quota int, by string) {
	for _, o := range opinions {
		if !trusted(o.Source) || !ValidStatus(o.Status) {
			continue
		}
		if Severity(o.Status) > Severity(status) {
			status, by = o.Status, o.Source
		}
		if o.Quota > 0 && (quota == 0 || o.Quota < quota) {
			quota = o.Quota
		}
	}
	return status, quota, by
}

// EffectiveKey is a key's publisher and status from the trusted sources'
// records: revoked if any says so; refused (an empty publisher) if two
// name different publishers.
func EffectiveKey(records []KeyRecord, trusted func(source string) bool) (publisherID, publicKey, status string) {
	for _, r := range records {
		if !trusted(r.Source) {
			continue
		}
		if publisherID == "" {
			publisherID, publicKey, status = r.PublisherID, r.PublicKey, r.Status
		} else if publisherID != r.PublisherID || publicKey != r.PublicKey {
			return "", "", ""
		}
		if r.Status == KeyRevoked {
			status = KeyRevoked
		}
	}
	if status != KeyActive && status != KeyRevoked {
		return "", "", ""
	}
	return publisherID, publicKey, status
}

// Newer tells whether an incoming record replaces a stored one: a newer
// time wins, and on a tie the more restrictive status.
func Newer(incomingUpdated, storedUpdated int64, incomingStatus, storedStatus string) bool {
	if incomingUpdated != storedUpdated {
		return incomingUpdated > storedUpdated
	}
	return Severity(incomingStatus) > Severity(storedStatus) ||
		(incomingStatus == KeyRevoked && storedStatus != KeyRevoked)
}

// Server is a published server's record.
type Server struct {
	ID             string
	PublisherID    string
	KeyID          string
	Instance       string
	Name           string
	Map            string
	Gametype       string
	Variant        string
	Players        int
	MaxPlayers     int
	Teams          bool
	InProgress     bool
	Password       bool
	Open           bool
	Dedicated      bool
	Kind           int
	Engine         int
	NetworkVersion int
	Build          string
	Region         string
	TunnelPort     int
	Listing        []byte
	HostKey        []byte
	Sequence       int64
	ListingTime    int64
	Observed       string
	Declared       string
	PublishAddress bool
	ProbeAddress   string
	Probe          string
	Reachable      bool
	ProbedAt       int64
	Hidden         bool
	HiddenReason   string
	Trusted        bool
	Closed         bool
	Serial         int64
	Created        int64
	Updated        int64
	// when (the master's clock) the record last took a newer listing of its
	// host: another host key, or a higher sequence
	ListingChanged int64
}

// Live tells whether a server's last publish is within ttl.
func (s *Server) Live(now time.Time, ttl time.Duration) bool {
	return !s.Closed && now.Unix()-s.Updated <= int64(ttl/time.Second)
}

// Application is an operator's application. Applications are made with
// the master's Discord bot (or an operator's command line); Email,
// EmailVerified, TokenHash, Address and AddressKey are the fields of the
// earlier web form's applications, kept readable.
type Application struct {
	ID string
	// shown beside the publisher's servers
	Name string
	// the applicant's e-mail address (the web form's applications only)
	Email string
	// the applicant's Discord username, and their Discord user id (the
	// bot's applications)
	Discord   string
	DiscordID string
	PublicKey string
	KeyID     string
	Servers   int
	Region    string
	Note      string
	ProofOK   bool
	// the mailed verification link's hash (the web form's only)
	TokenHash     string
	EmailVerified bool
	Address       string
	// what the address's applications are counted under (netaddr.Key)
	AddressKey  string
	Status      string
	Reason      string
	PublisherID string
	// who decided it (the audit log's actor)
	DecidedBy string
	Created   int64
	Updated   int64
	// the bot's log channel message for the application (its channel and
	// message ids), the status it shows, and whether it is still to be
	// posted
	LogChannel string
	LogMessage string
	LogStatus  string
	LogQueued  bool
	// the status the Discord applicant was last told of
	ToldStatus string
}

// AuditEntry is a line of the audit log.
type AuditEntry struct {
	N      int64  `json:"n"`
	Time   int64  `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}
