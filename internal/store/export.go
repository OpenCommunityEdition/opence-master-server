package store

import (
	"errors"
	"regexp"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

// ExportFormat names the export file's format.
const ExportFormat = "opence-master-export-1"

// ExportedPublisher is a publisher with every master's opinion and key
// records.
type ExportedPublisher struct {
	model.Publisher
	Opinions []model.Opinion   `json:"opinions"`
	Keys     []model.KeyRecord `json:"keys"`
}

// ExportedApplication is an application in an export.
type ExportedApplication struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	Discord       string `json:"discord"`
	DiscordID     string `json:"discord_id,omitempty"`
	PublicKey     string `json:"public_key"`
	KeyID         string `json:"key_id"`
	Servers       int    `json:"servers"`
	Region        string `json:"region"`
	Note          string `json:"note"`
	ProofOK       bool   `json:"proof_ok"`
	TokenHash     string `json:"token_hash"`
	EmailVerified bool   `json:"email_verified"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	PublisherID   string `json:"publisher_id"`
	DecidedBy     string `json:"decided_by,omitempty"`
	Created       int64  `json:"created"`
	Updated       int64  `json:"updated"`
}

// Export is the backup (and peers' import) file.
type Export struct {
	Format       string                `json:"format"`
	Master       string                `json:"master"`
	Time         int64                 `json:"time"`
	Publishers   []ExportedPublisher   `json:"publishers"`
	Applications []ExportedApplication `json:"applications,omitempty"`
}

// Export writes every publisher (with contacts and applications unless
// public).
func (s *Store) Export(masterKeyID string, public bool) (*Export, error) {
	out := &Export{Format: ExportFormat, Master: masterKeyID, Time: s.now(), Publishers: []ExportedPublisher{}}
	publishers, err := s.Publishers()
	if err != nil {
		return nil, err
	}
	opinions, err := s.Opinions("")
	if err != nil {
		return nil, err
	}
	keys, err := s.PublisherKeys("")
	if err != nil {
		return nil, err
	}
	byPublisher := map[string]*ExportedPublisher{}
	for _, p := range publishers {
		if public {
			p.Email, p.Discord, p.DiscordID = "", "", ""
		}
		out.Publishers = append(out.Publishers, ExportedPublisher{Publisher: p, Opinions: []model.Opinion{},
			Keys: []model.KeyRecord{}})
	}
	for i := range out.Publishers {
		byPublisher[out.Publishers[i].ID] = &out.Publishers[i]
	}
	for _, o := range opinions {
		if p := byPublisher[o.PublisherID]; p != nil {
			p.Opinions = append(p.Opinions, o)
		}
	}
	for _, k := range keys {
		if p := byPublisher[k.PublisherID]; p != nil {
			p.Keys = append(p.Keys, k)
		}
	}
	if public {
		return out, nil
	}
	applications, err := s.Applications("", 1<<30)
	if err != nil {
		return nil, err
	}
	for _, a := range applications {
		out.Applications = append(out.Applications, ExportedApplication{
			ID: a.ID, Name: a.Name, Email: a.Email, Discord: a.Discord, DiscordID: a.DiscordID,
			PublicKey: a.PublicKey, KeyID: a.KeyID, Servers: a.Servers, Region: a.Region, Note: a.Note,
			ProofOK: a.ProofOK, TokenHash: a.TokenHash, EmailVerified: a.EmailVerified, Status: a.Status,
			Reason: a.Reason, PublisherID: a.PublisherID, DecidedBy: a.DecidedBy, Created: a.Created,
			Updated: a.Updated,
		})
	}
	return out, nil
}

// ImportCounts says what an import changed, and how many records it
// refused.
type ImportCounts struct {
	Publishers, Opinions, Keys, Applications, Refused int
}

var (
	publisherIDPattern   = regexp.MustCompile(`^p_[a-z0-9]{1,32}$`)
	applicationIDPattern = regexp.MustCompile(`^a_[a-z0-9]{1,32}$`)
	keyIDPattern         = regexp.MustCompile(`^[0-9a-f]{16}$`)
	discordIDPattern     = regexp.MustCompile(`^[0-9]{0,20}$`)
)

// ValidPublicKey tells whether a public key's text is exactly as the master
// writes it (ed25519:<64 lowercase hex>), of a point that is not of small
// order, and its key id is keyID.
func ValidPublicKey(text, keyID string) bool {
	public, err := sign.ParsePublicKey(text)
	return err == nil && sign.PublicKeyText(public) == text && sign.KeyID(public) == keyID
}

func printable(text string, maximum int) bool {
	if len(text) > maximum {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] >= 0x7f {
			return false
		}
	}
	return true
}

// Import merges an export made by the master whose key id is e.Master:
// new publishers are added, and each master's opinion and key record
// replaces the stored one only if it is newer. self is this master's key
// id: records in this master's name (source self) are taken only from this
// master's own export, so that a peer's file cannot put words in this
// master's mouth, which it would then share as its own. A publisher new
// here is recorded as come from e.Master, whatever origin another master's
// file claims for it (this master's own file keeps its origins). Records
// with an unknown status, a key that does not parse or is not its key id's,
// or a key another publisher holds here are refused.
func (s *Store) Import(e *Export, self string) (ImportCounts, error) {
	var counts ImportCounts
	if !keyIDPattern.MatchString(e.Master) {
		return counts, errors.New("the export's master is not a key id")
	}
	own := e.Master == self
	for _, p := range e.Publishers {
		if !publisherIDPattern.MatchString(p.ID) || !keyIDPattern.MatchString(p.Origin) ||
			!printable(p.Name, 32) || !printable(p.Email, 254) || !printable(p.Discord, 37) ||
			!discordIDPattern.MatchString(p.DiscordID) {
			counts.Refused++
			continue
		}
		if !own {
			p.Origin = e.Master
		}
		added, err := s.InsertPublisherIfAbsent(&p.Publisher)
		if err != nil {
			return counts, err
		}
		if added {
			counts.Publishers++
		}
		for _, o := range p.Opinions {
			o.PublisherID = p.ID
			if !model.ValidStatus(o.Status) || !keyIDPattern.MatchString(o.Source) || (o.Source == self && !own) ||
				o.Quota < 0 || o.Quota > 1000 {
				counts.Refused++
				continue
			}
			changed, err := s.MergeOpinion(o)
			if err != nil {
				return counts, err
			}
			if changed {
				counts.Opinions++
			}
		}
		for _, k := range p.Keys {
			k.PublisherID = p.ID
			if (k.Status != model.KeyActive && k.Status != model.KeyRevoked) || !keyIDPattern.MatchString(k.Source) ||
				(k.Source == self && !own) || !ValidPublicKey(k.PublicKey, k.KeyID) {
				counts.Refused++
				continue
			}
			others, err := s.KeyRecords(k.KeyID)
			if err != nil {
				return counts, err
			}
			conflict := false
			for _, other := range others {
				if other.PublisherID != p.ID || other.PublicKey != k.PublicKey {
					conflict = true
				}
			}
			if conflict {
				counts.Refused++
				continue
			}
			changed, err := s.MergeKey(k)
			if err != nil {
				return counts, err
			}
			if changed {
				counts.Keys++
			}
		}
	}
	for _, a := range e.Applications {
		if !applicationIDPattern.MatchString(a.ID) || !ValidPublicKey(a.PublicKey, a.KeyID) ||
			(a.Status != model.ApplicationPending && a.Status != model.ApplicationApproved &&
				a.Status != model.ApplicationDenied) || !printable(a.Name, 32) || !printable(a.Email, 254) ||
			!printable(a.Discord, 37) || !discordIDPattern.MatchString(a.DiscordID) || !printable(a.DecidedBy, 80) ||
			(a.PublisherID != "" && !publisherIDPattern.MatchString(a.PublisherID)) {
			counts.Refused++
			continue
		}
		// (an imported application is not posted to the log channel, and its
		// Discord applicant is not told of it again)
		result, err := s.db.Exec(`INSERT OR IGNORE INTO applications (`+applicationColumns+`) VALUES (`+
			placeholders(applicationColumnCount)+`)`, applicationValues(&model.Application{
			ID: a.ID, Name: a.Name, Email: a.Email, Discord: a.Discord, DiscordID: a.DiscordID, PublicKey: a.PublicKey,
			KeyID: a.KeyID, Servers: a.Servers, Region: a.Region, Note: a.Note, ProofOK: a.ProofOK,
			TokenHash: a.TokenHash, EmailVerified: a.EmailVerified, Status: a.Status, Reason: a.Reason,
			PublisherID: a.PublisherID, DecidedBy: a.DecidedBy, Created: a.Created, Updated: a.Updated,
			ToldStatus: a.Status})...)
		if err != nil {
			return counts, err
		}
		if n, _ := result.RowsAffected(); n == 1 {
			counts.Applications++
		}
	}
	return counts, nil
}
