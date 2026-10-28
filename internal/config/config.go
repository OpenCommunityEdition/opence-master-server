// Package config reads the master's options: each is an environment
// variable (MASTER_*) and a command-line flag, the flag winning.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is every option.
type Config struct {
	Name                string
	Contact             string
	DataPolicy          string
	PublicURL           string
	DB                  string
	Key                 string
	AdminToken          string
	NotifyWebhook       string
	DiscordToken        string
	DiscordGuild        string
	DiscordChannel      string
	DiscordRoles        string
	DiscordInvite       string
	Listen              string
	TLSCert             string
	TLSKey              string
	Peers               string
	PeersTrust          string
	PeersInterval       time.Duration
	ListUnreachable     bool
	ServeAddresses      bool
	CAFile              string
	Probe               bool
	ProbeListen         string
	TrustedProxies      string
	SMTPAddr            string
	SMTPUser            string
	SMTPPassword        string
	SMTPTLS             string
	MailFrom            string
	DefaultQuota        int
	PublishInterval     time.Duration
	ListPerMinute       int
	ApplicationsPerDay  int
	ApplicationsPerHour int
	ApplicationsPerKey  int
	RequireProof        bool
	LogAddresses        bool
	LogLevel            string
	Updates             string
	UpdateURL           string
	UpdateKey           string
	UpdateInterval      time.Duration
	Netlist             bool
	NetlistInterval     time.Duration
	NetlistTorInterval  time.Duration
	NetlistASNURLs      []string
	NetlistIPToASNURL   string
	NetlistListURLs     []string
	NetlistTorURL       string
}

// Option describes one option, for the flags, the environment and the help.
type Option struct {
	Env, Flag, Help, Default string
}

// the secrets: their variables' values are not made their flags' defaults,
// so the help never shows them
var secrets = map[string]bool{"MASTER_ADMIN_TOKEN": true, "MASTER_SMTP_PASSWORD": true, "MASTER_DISCORD_TOKEN": true}

// Options is every option, in the help's order.
var Options = []Option{
	{"MASTER_NAME", "name", "the master's name, shown in its lists and pages (else set by the first launch's setup)", ""},
	{"MASTER_CONTACT", "contact", "the admin contact: an e-mail address or a URL (optional; else set on the admin pages)", ""},
	{"MASTER_DATA_POLICY", "data-policy", "the data policy shown on the pages",
		"Addresses are kept 7 days for probes and abuse handling and never served; no data is sold."},
	{"MASTER_PUBLIC_URL", "public-url", "the master's public HTTPS origin, for links in mails and pages", ""},
	{"MASTER_DB", "db", "the SQLite database file", "master.db"},
	{"MASTER_KEY", "key", "the master key: a key file's path, or its 64 hexadecimal digits", "master.key"},
	{"MASTER_ADMIN_TOKEN", "admin-token", "the admin pages' token, 32 characters or more (else made by the first launch's setup)", ""},
	{"MASTER_NOTIFY_WEBHOOK", "notify-webhook", "a Discord-compatible webhook told of new applications (besides the bot's log channel)", ""},
	{"MASTER_DISCORD_TOKEN", "discord-token", "the Discord bot's token, which takes the applications (else set on the admin pages)", ""},
	{"MASTER_DISCORD_GUILD", "discord-guild", "the Discord server (guild) id where the bot's /apply and /configure are (else set on the admin pages)", ""},
	{"MASTER_DISCORD_CHANNEL", "discord-channel", "the Discord channel id where the bot posts applications (else chosen with the bot's /configure)", ""},
	{"MASTER_DISCORD_APPROVER_ROLES", "discord-approver-roles", "the Discord role ids, separated by commas, whose members approve and deny (else chosen with the bot's /configure)", ""},
	{"MASTER_DISCORD_INVITE", "discord-invite", "an invite to the Discord server, shown on the /apply page (else set on the admin pages)", ""},
	{"MASTER_LISTEN", "listen", "the HTTP listener's address", "127.0.0.1:8090"},
	{"MASTER_TLS_CERT", "tls-cert", "a certificate file, to serve HTTPS directly", ""},
	{"MASTER_TLS_KEY", "tls-key", "the certificate's key file", ""},
	{"MASTER_PEERS", "peers", "peer masters: \"<url> ed25519:<hex>\" separated by commas, or a masters.txt file", ""},
	{"MASTER_PEERS_TRUST", "peers-trust", "the peers whose approvals are imported: all, none, or key ids", "all"},
	{"MASTER_PEERS_INTERVAL", "peers-interval", "how often the peers' approvals are fetched", "60s"},
	{"MASTER_LIST_UNREACHABLE", "list-unreachable", "list servers whose probe failed, as reachable: false", "false"},
	{"MASTER_SERVE_ADDRESSES", "serve-addresses", "serve the address of servers that publish one", "false"},
	{"MASTER_CA_FILE", "ca-file", "extra certificate authorities (PEM) for peers and webhooks", ""},
	{"MASTER_PROBE", "probe", "probe servers' UDP ports before listing them", "true"},
	{"MASTER_PROBE_LISTEN", "probe-listen", "the probe socket's address ([::]:0: IPv6 and IPv4, else IPv4 only)", "[::]:0"},
	{"MASTER_TRUSTED_PROXIES", "trusted-proxies", "reverse proxies (addresses or CIDRs, commas) whose X-Forwarded-* are believed", ""},
	{"MASTER_SMTP_ADDR", "smtp-addr", "an SMTP server (host:port) for mail; none: mail goes to the log", ""},
	{"MASTER_SMTP_USER", "smtp-user", "the SMTP user", ""},
	{"MASTER_SMTP_PASSWORD", "smtp-password", "the SMTP password", ""},
	{"MASTER_SMTP_TLS", "smtp-tls", "auto (implicit TLS on port 465, else STARTTLS), starttls, tls, or none (loopback only)", "auto"},
	{"MASTER_MAIL_FROM", "mail-from", "the mails' From address", ""},
	{"MASTER_DEFAULT_QUOTA", "default-quota", "servers at once for a new publisher", "4"},
	{"MASTER_PUBLISH_MIN_INTERVAL", "publish-min-interval", "the least time between a server's publishes (a burst of 2)", "5s"},
	{"MASTER_LIST_RATE", "list-rate", "list requests a minute per address", "60"},
	{"MASTER_APPLICATIONS_PER_DAY", "applications-per-day", "applications a day per Discord user", "3"},
	{"MASTER_APPLICATIONS_PER_HOUR", "applications-per-hour", "applications an hour in all past which the admins " +
		"are alerted (once) and those without a proof of key are refused", "100"},
	{"MASTER_APPLICATIONS_PER_KEY", "applications-per-key", "applications a day per publisher key", "3"},
	{"MASTER_REQUIRE_PROOF", "require-proof", "refuse applications without a proof of key", "true"},
	{"MASTER_LOG_ADDRESSES", "log-addresses", "write addresses in the log", "false"},
	{"MASTER_LOG_LEVEL", "log-level", "debug, info, warn or error", "info"},
	{"MASTER_UPDATES", "updates", "notify (tell the admins of a new release; they update with a button), auto " +
		"(install it at once) or off", "notify"},
	{"MASTER_UPDATE_INTERVAL", "update-interval", "how often the releases are checked", "6h"},
	{"MASTER_UPDATE_URL", "update-url", "the latest release, on GitHub's API (a fork's)",
		"https://api.github.com/repos/OpenCommunityEdition/opence-master-server/releases/latest"},
	{"MASTER_UPDATE_KEY", "update-key", "the release key's public key, 64 hex digits (a fork's; default the project's)", ""},
	{"MASTER_NETLIST", "netlist", "build and serve the netlist (GET /v1/netlist): on or off", "on"},
	{"MASTER_NETLIST_INTERVAL", "netlist-interval", "how often the netlist's sources are fetched (but Tor's)", "24h"},
	{"MASTER_NETLIST_TOR_INTERVAL", "netlist-tor-interval", "how often the Tor exits are fetched", "1h"},
	{"MASTER_NETLIST_ASN_URLS", "netlist-asn-urls", "lists of autonomous systems (\"AS<n>\" a line), separated by " +
		"commas, expanded to their ranges with iptoasn (empty: none)", DefaultASNURLs},
	{"MASTER_NETLIST_IPTOASN_URL", "netlist-iptoasn-url", "iptoasn.com's ip2asn-v4.tsv.gz (empty: none)",
		"https://iptoasn.com/data/ip2asn-v4.tsv.gz"},
	{"MASTER_NETLIST_LIST_URLS", "netlist-list-urls", "lists of IPv4 CIDRs (one a line), separated by commas, " +
		"taken whole (empty: none)", DefaultListURLs},
	{"MASTER_NETLIST_TOR_URL", "netlist-tor-url", "the Tor exits' addresses, one a line (empty: none)",
		"https://check.torproject.org/torbulkexitlist"},
}

// The netlist's default sources (X4BNet's lists_vpn, MIT).
const (
	DefaultASNURLs = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt," +
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt"
	DefaultListURLs = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt," +
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
)

// Flags adds every option to a flag set, its default from the environment.
func Flags(set *flag.FlagSet) map[string]*string {
	values := map[string]*string{}
	for _, o := range Options {
		value := o.Default
		if env, ok := os.LookupEnv(o.Env); ok && !secrets[o.Env] {
			value = env
		}
		values[o.Env] = set.String(o.Flag, value, o.Help+" ("+o.Env+")")
	}
	return values
}

// secret is a secret option's value: its flag's, else its variable's.
func secret(values map[string]*string, env string) string {
	if value := strings.TrimSpace(*values[env]); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(env))
}

func duration(text string) (time.Duration, error) {
	if n, err := strconv.Atoi(text); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(text)
}

func boolean(text string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("%q is not true or false", text)
}

// Load turns the flags' values into a Config.
func Load(values map[string]*string) (*Config, error) {
	get := func(env string) string { return strings.TrimSpace(*values[env]) }
	c := &Config{
		Name: get("MASTER_NAME"), Contact: get("MASTER_CONTACT"), DataPolicy: get("MASTER_DATA_POLICY"),
		PublicURL: strings.TrimRight(get("MASTER_PUBLIC_URL"), "/"), DB: get("MASTER_DB"), Key: get("MASTER_KEY"),
		AdminToken: secret(values, "MASTER_ADMIN_TOKEN"), NotifyWebhook: get("MASTER_NOTIFY_WEBHOOK"),
		DiscordToken: secret(values, "MASTER_DISCORD_TOKEN"), DiscordGuild: get("MASTER_DISCORD_GUILD"),
		DiscordChannel: get("MASTER_DISCORD_CHANNEL"), DiscordRoles: get("MASTER_DISCORD_APPROVER_ROLES"),
		DiscordInvite: get("MASTER_DISCORD_INVITE"),
		Listen:        get("MASTER_LISTEN"), TLSCert: get("MASTER_TLS_CERT"), TLSKey: get("MASTER_TLS_KEY"),
		Peers: get("MASTER_PEERS"), PeersTrust: get("MASTER_PEERS_TRUST"), CAFile: get("MASTER_CA_FILE"),
		ProbeListen: get("MASTER_PROBE_LISTEN"), TrustedProxies: get("MASTER_TRUSTED_PROXIES"),
		SMTPAddr: get("MASTER_SMTP_ADDR"), SMTPUser: get("MASTER_SMTP_USER"), SMTPPassword: secret(values, "MASTER_SMTP_PASSWORD"),
		SMTPTLS: strings.ToLower(get("MASTER_SMTP_TLS")), MailFrom: get("MASTER_MAIL_FROM"), LogLevel: get("MASTER_LOG_LEVEL"),
		Updates: strings.ToLower(get("MASTER_UPDATES")), UpdateURL: get("MASTER_UPDATE_URL"),
		UpdateKey: get("MASTER_UPDATE_KEY"),
	}
	var err error
	var errs []error
	check := func(e error, env string) {
		if e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", env, e))
		}
	}
	c.UpdateInterval, err = duration(get("MASTER_UPDATE_INTERVAL"))
	check(err, "MASTER_UPDATE_INTERVAL")
	switch c.Updates {
	case "notify", "auto", "off":
	case "":
		c.Updates = "notify"
	default:
		errs = append(errs, errors.New("MASTER_UPDATES: notify, auto or off"))
	}
	if err == nil && c.UpdateInterval < 10*time.Minute {
		errs = append(errs, errors.New("MASTER_UPDATE_INTERVAL: 10 minutes at least"))
	}
	c.PeersInterval, err = duration(get("MASTER_PEERS_INTERVAL"))
	check(err, "MASTER_PEERS_INTERVAL")
	c.PublishInterval, err = duration(get("MASTER_PUBLISH_MIN_INTERVAL"))
	check(err, "MASTER_PUBLISH_MIN_INTERVAL")
	c.ListUnreachable, err = boolean(get("MASTER_LIST_UNREACHABLE"))
	check(err, "MASTER_LIST_UNREACHABLE")
	c.ServeAddresses, err = boolean(get("MASTER_SERVE_ADDRESSES"))
	check(err, "MASTER_SERVE_ADDRESSES")
	c.Probe, err = boolean(get("MASTER_PROBE"))
	check(err, "MASTER_PROBE")
	c.RequireProof, err = boolean(get("MASTER_REQUIRE_PROOF"))
	check(err, "MASTER_REQUIRE_PROOF")
	c.LogAddresses, err = boolean(get("MASTER_LOG_ADDRESSES"))
	check(err, "MASTER_LOG_ADDRESSES")
	c.DefaultQuota, err = strconv.Atoi(get("MASTER_DEFAULT_QUOTA"))
	check(err, "MASTER_DEFAULT_QUOTA")
	c.ListPerMinute, err = strconv.Atoi(get("MASTER_LIST_RATE"))
	check(err, "MASTER_LIST_RATE")
	c.ApplicationsPerDay, err = strconv.Atoi(get("MASTER_APPLICATIONS_PER_DAY"))
	check(err, "MASTER_APPLICATIONS_PER_DAY")
	c.ApplicationsPerHour, err = strconv.Atoi(get("MASTER_APPLICATIONS_PER_HOUR"))
	check(err, "MASTER_APPLICATIONS_PER_HOUR")
	c.ApplicationsPerKey, err = strconv.Atoi(get("MASTER_APPLICATIONS_PER_KEY"))
	check(err, "MASTER_APPLICATIONS_PER_KEY")
	if c.DefaultQuota < 1 || c.DefaultQuota > 1000 {
		errs = append(errs, errors.New("MASTER_DEFAULT_QUOTA: 1 to 1000"))
	}
	switch c.SMTPTLS {
	case "auto", "starttls", "tls", "none":
	case "":
		c.SMTPTLS = "auto"
	default:
		errs = append(errs, errors.New("MASTER_SMTP_TLS: auto, starttls, tls or none"))
	}
	if c.SMTPTLS == "none" && c.SMTPAddr != "" && !loopbackHost(c.SMTPAddr) {
		errs = append(errs, errors.New("MASTER_SMTP_TLS: none only for an SMTP server on loopback"))
	}
	c.Netlist, err = boolean(get("MASTER_NETLIST"))
	check(err, "MASTER_NETLIST")
	c.NetlistInterval, err = duration(get("MASTER_NETLIST_INTERVAL"))
	check(err, "MASTER_NETLIST_INTERVAL")
	if err == nil && c.NetlistInterval < time.Hour {
		errs = append(errs, errors.New("MASTER_NETLIST_INTERVAL: an hour at least"))
	}
	c.NetlistTorInterval, err = duration(get("MASTER_NETLIST_TOR_INTERVAL"))
	check(err, "MASTER_NETLIST_TOR_INTERVAL")
	if err == nil && c.NetlistTorInterval < 5*time.Minute {
		errs = append(errs, errors.New("MASTER_NETLIST_TOR_INTERVAL: 5 minutes at least"))
	}
	c.NetlistASNURLs, err = sourceURLs(get("MASTER_NETLIST_ASN_URLS"))
	check(err, "MASTER_NETLIST_ASN_URLS")
	c.NetlistListURLs, err = sourceURLs(get("MASTER_NETLIST_LIST_URLS"))
	check(err, "MASTER_NETLIST_LIST_URLS")
	var one []string
	one, err = sourceURLs(get("MASTER_NETLIST_IPTOASN_URL"))
	check(err, "MASTER_NETLIST_IPTOASN_URL")
	if len(one) > 1 {
		errs = append(errs, errors.New("MASTER_NETLIST_IPTOASN_URL: one URL"))
	} else if len(one) == 1 {
		c.NetlistIPToASNURL = one[0]
	}
	one, err = sourceURLs(get("MASTER_NETLIST_TOR_URL"))
	check(err, "MASTER_NETLIST_TOR_URL")
	if len(one) > 1 {
		errs = append(errs, errors.New("MASTER_NETLIST_TOR_URL: one URL"))
	} else if len(one) == 1 {
		c.NetlistTorURL = one[0]
	}
	if c.PeersInterval < time.Second {
		errs = append(errs, errors.New("MASTER_PEERS_INTERVAL: at least a second"))
	}
	if _, err := c.Proxies(); err != nil {
		check(err, "MASTER_TRUSTED_PROXIES")
	}
	return c, errors.Join(errs...)
}

// CheckServe checks the options serving takes. None is required: the first
// launch's setup (the admin pages) names the master and makes the admin
// token.
func (c *Config) CheckServe() error {
	var errs []error
	if c.AdminToken != "" && len(c.AdminToken) < 32 {
		errs = append(errs, errors.New("MASTER_ADMIN_TOKEN must be 32 characters or more"))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("MASTER_TLS_CERT and MASTER_TLS_KEY go together"))
	}
	if len(c.Name) > 64 {
		errs = append(errs, errors.New("MASTER_NAME: 64 characters at most"))
	}
	return errors.Join(errs...)
}

// sourceURLs reads URLs separated by commas: https, or http to loopback.
func sourceURLs(text string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopbackHost(u.Host))) {
			return nil, fmt.Errorf("%q is not an https:// URL (http:// only to loopback)", part)
		}
		out = append(out, part)
	}
	return out, nil
}

func loopbackHost(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

// Proxies reads MASTER_TRUSTED_PROXIES.
func (c *Config) Proxies() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.FieldsFunc(c.TrustedProxies, func(r rune) bool { return r == ',' || r == ' ' }) {
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			out = append(out, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()))
	}
	return out, nil
}
