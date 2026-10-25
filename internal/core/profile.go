package core

import (
	"strings"
)

// The master's name and contact in the database, set on first launch (the
// admin pages' setup) unless MASTER_NAME and MASTER_CONTACT set them.
const (
	keyName    = "master.name"
	keyContact = "master.contact"
)

// UnnamedMaster is the name shown until the setup names the master.
const UnnamedMaster = "OpenCE master (not set up)"

// Profile is the master's name and admin contact.
type Profile struct {
	Name, Contact string
	// the fields the environment sets: "name", "contact"
	FromEnv map[string]bool
}

// loadProfile reads the name and the contact: the environment's, else the
// database's.
func (m *Master) loadProfile() error {
	id := &Profile{FromEnv: map[string]bool{}}
	for _, f := range []struct {
		name, key, env string
		target         *string
	}{{"name", keyName, m.Config.Name, &id.Name}, {"contact", keyContact, m.Config.Contact, &id.Contact}} {
		if f.env != "" {
			*f.target, id.FromEnv[f.name] = f.env, true
			continue
		}
		value, _, err := m.Store.Setting(f.key)
		if err != nil {
			return err
		}
		*f.target = value
	}
	m.profile.Store(id)
	return nil
}

// Profile returns the master's name (empty until it is set up) and contact.
func (m *Master) Profile() Profile { return *m.profile.Load() }

// Name is the master's name, shown in its lists, pages and messages.
func (m *Master) Name() string {
	if name := m.profile.Load().Name; name != "" {
		return name
	}
	return UnnamedMaster
}

// Contact is the master's admin contact (empty: none given).
func (m *Master) Contact() string { return m.profile.Load().Contact }

// Named tells whether the master has a name (the setup is done).
func (m *Master) Named() bool { return m.profile.Load().Name != "" }

// CheckProfile checks a name (required) and a contact (optional).
func CheckProfile(name, contact string) error {
	switch {
	case name == "" || len(name) > 64 || !Printable(name):
		return &FieldError{"name", "1 to 64 printable ASCII characters"}
	case len(contact) > 200 || !Printable(contact):
		return &FieldError{"contact", "an e-mail address or a URL: 200 printable ASCII characters at most"}
	}
	return nil
}

// SetProfile stores the name and the contact (those the environment does
// not set) and writes the change to the audit log.
func (m *Master) SetProfile(name, contact, actor string) error {
	name, contact = strings.TrimSpace(name), strings.TrimSpace(contact)
	current := m.Profile()
	if current.FromEnv["name"] {
		name = current.Name
	}
	if current.FromEnv["contact"] {
		contact = current.Contact
	}
	if err := CheckProfile(name, contact); err != nil {
		return err
	}
	var changes []string
	for _, f := range []struct{ field, key, old, value string }{
		{"name", keyName, current.Name, name}, {"contact", keyContact, current.Contact, contact}} {
		if current.FromEnv[f.field] || f.old == f.value {
			continue
		}
		if err := m.Store.SetSetting(f.key, f.value); err != nil {
			return err
		}
		changes = append(changes, f.field+" "+f.value)
	}
	if len(changes) == 0 {
		return nil
	}
	if err := m.loadProfile(); err != nil {
		return err
	}
	_ = m.Store.Audit(actor, "master-settings", "", strings.Join(changes, ", "))
	return nil
}
