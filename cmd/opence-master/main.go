// opence-master is an OpenCE master server: it lists the dedicated servers
// of approved operators, each publish signed with the operator's key, and
// signs the list it serves. docs/master_protocol.md in the game's
// repository is the protocol it implements.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/admin"
	"github.com/OpenCommunityEdition/opence-master-server/internal/api"
	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/discord"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/metrics"
	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
	"github.com/OpenCommunityEdition/opence-master-server/internal/netlist"
	"github.com/OpenCommunityEdition/opence-master-server/internal/peers"
	"github.com/OpenCommunityEdition/opence-master-server/internal/probe"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/update"
	"github.com/OpenCommunityEdition/opence-master-server/internal/view"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

const usage = `opence-master: an OpenCE master server (protocol 1)

Usage:
  opence-master serve [options]                 serve the master
  opence-master keygen --out <file> [--force | --keep]
                                                make a master key and print its public key (--keep:
                                                keep an existing one and print its public key)
  opence-master list-applications [--all]       the applications waiting (or all)
  opence-master challenge [--discord-id <id>]   a nonce for an application's proof of key
  opence-master add-application --display-name <name> --public-key ed25519:<hex> [--servers n]
        [--region r] [--note t] [--proof-nonce <nonce> --proof-signature <hex>]
        [--discord-id <id> --discord-name <name>]
                                                an application made by an operator (applicants use
                                                the Discord bot's /apply)
  opence-master approve <application> [--quota n]
  opence-master deny <application> --reason <text>
  opence-master list-publishers                 every publisher and its status
  opence-master suspend <publisher> [--reason <text>]
  opence-master resume <publisher>
  opence-master revoke <publisher or key id> [--reason <text>]
  opence-master quota <publisher> <n>
  opence-master export [--public] [--out <file>]   the publishers (and applications) as JSON
  opence-master import <file>                   merge an export (a backup's, or a peer's)
  opence-master health [--url <url>]           exit 0 if the master's /healthz answers (for containers)
  opence-master update [--check]               install the latest release, which the master runs at its
                                                next start (the admin pages and the Discord bot's notice
                                                update a running master and restart it)
  opence-master version

Every option is also an environment variable; "opence-master serve -h" lists them.
`

// exit codes: 1 a failure, 2 bad usage or configuration
func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]
	var err error
	switch command {
	case "serve":
		err = serve(args)
	case "keygen":
		err = keygen(args)
	case "approve", "deny", "suspend", "resume", "revoke", "quota", "list-applications", "list-publishers",
		"export", "import", "challenge", "add-application":
		err = administer(command, args)
	case "health":
		err = health(args)
	case "update":
		err = updateCommand(args)
	case "version", "--version":
		fmt.Printf("opence-master %s (protocol %d)\n", core.Version, core.Protocol)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "opence-master: unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "opence-master:", err)
		var u usageError
		if errors.As(err, &u) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

type usageError struct{ error }

// parse reads flags anywhere among the arguments, returning the others.
func parse(set *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := set.Parse(args); err != nil {
			return nil, usageError{err}
		}
		if set.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, set.Arg(0))
		args = set.Args()[1:]
	}
}

func logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// tlsConfig is the TLS configuration for peers, the webhook and SMTP: the
// system's authorities and MASTER_CA_FILE's.
func tlsConfig(caFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("MASTER_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("MASTER_CA_FILE holds no certificate")
		}
		config.RootCAs = pool
	}
	return config, nil
}

// httpClient is the client for peers and the webhook. It follows no
// redirect: a peer's or a webhook's URL is the one configured, and a
// redirect elsewhere (to an internal address, say) is answered as an error.
func httpClient(config *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config.Clone()
	return &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// sourceClient is the client for the netlist's sources: it follows
// redirects to HTTPS URLs only.
func sourceClient(config *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config.Clone()
	return &http.Client{Transport: transport, Timeout: netlist.FetchTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("more than 5 redirects")
			}
			if r.URL.Scheme != "https" {
				return errors.New("a redirect to a URL that is not https://")
			}
			return nil
		}}
}

// netlistSources are the netlist's sources the options name.
func netlistSources(cfg *config.Config) []netlist.Source {
	var out []netlist.Source
	for _, u := range cfg.NetlistASNURLs {
		out = append(out, netlist.NewSource(netlist.KindASN, u))
	}
	if cfg.NetlistIPToASNURL != "" {
		out = append(out, netlist.NewSource(netlist.KindIPToASN, cfg.NetlistIPToASNURL))
	}
	for _, u := range cfg.NetlistListURLs {
		out = append(out, netlist.NewSource(netlist.KindList, u))
	}
	if cfg.NetlistTorURL != "" {
		out = append(out, netlist.NewSource(netlist.KindTor, cfg.NetlistTorURL))
	}
	return out
}

// probeSocket opens the probe's UDP socket: for an unspecified IPv6 address
// ("[::]:0", the default) a dual-stack socket, which reaches IPv4 servers
// too, or an IPv4 one where the machine has no IPv6.
func probeSocket(listen string, log *slog.Logger) (*net.UDPConn, error) {
	address, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, usageError{fmt.Errorf("MASTER_PROBE_LISTEN: %w", err)}
	}
	if address.IP != nil && address.IP.To4() != nil {
		return net.ListenUDP("udp4", address)
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil && (address.IP == nil || address.IP.IsUnspecified()) {
		log.Warn("probe: no IPv6 socket, probing IPv4 servers only", "err", err)
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: address.Port})
	}
	return conn, err
}

// open loads the configuration, the key and the database for a command.
func open(set *flag.FlagSet, values map[string]*string, sync bool) (*core.Master, func(), error) {
	cfg, err := config.Load(values)
	if err != nil {
		return nil, nil, usageError{err}
	}
	log := logger(cfg.LogLevel)
	key, err := sign.LoadSeed(cfg.Key)
	if err != nil {
		return nil, nil, usageError{fmt.Errorf("the master key (MASTER_KEY=%s): %w; make one with "+
			"\"opence-master keygen --out %s\"", cfg.Key, err, cfg.Key)}
	}
	st, err := store.Open(cfg.DB)
	if err != nil {
		return nil, nil, fmt.Errorf("the database %s: %w", cfg.DB, err)
	}
	config, err := tlsConfig(cfg.CAFile)
	if err != nil {
		st.Close()
		return nil, nil, usageError{err}
	}
	notifier := &mail.Notifier{SMTPAddr: cfg.SMTPAddr, User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.MailFrom, TLS: cfg.SMTPTLS, TLSConfig: config, Webhook: cfg.NotifyWebhook,
		Client: httpClient(config), Log: log, Sync: sync}
	m, err := core.New(st, key, cfg, notifier, log)
	if err != nil {
		st.Close()
		return nil, nil, usageError{err}
	}
	return m, func() { st.Close() }, nil
}

func serve(args []string) error {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	values := config.Flags(set)
	if _, err := parse(set, args); err != nil {
		return err
	}
	cfg, err := config.Load(values)
	if err != nil {
		return usageError{err}
	}
	if err := cfg.CheckServe(); err != nil {
		return usageError{fmt.Errorf("refusing to start:\n%w", err)}
	}
	if err := discord.CheckEnvironment(cfg); err != nil {
		return usageError{fmt.Errorf("refusing to start:\n%w", err)}
	}
	if err := firstKey(cfg, logger(cfg.LogLevel)); err != nil {
		return err
	}
	updater, err := newUpdater(cfg, logger(cfg.LogLevel))
	if err != nil {
		return usageError{err}
	}
	// (an installed release newer than this program runs instead: Launch
	// returns only when there is none)
	update.Launch(updater.Dir, core.Version, logger(cfg.LogLevel))
	if err := update.BackupDatabase(cfg.DB, core.Version, logger(cfg.LogLevel)); err != nil {
		return err
	}
	m, closeOnce, err := open(set, values, false)
	if err != nil {
		return err
	}
	var closing sync.Once
	closeStore := func() { closing.Do(closeOnce) }
	defer closeStore()
	log := m.Log
	updater.Log = log
	proxies, _ := cfg.Proxies()
	clients := &httpx.Clients{Proxies: proxies}
	counters := metrics.New()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var prober *probe.Prober
	if cfg.Probe {
		conn, err := probeSocket(cfg.ProbeListen, log)
		if err != nil {
			var u usageError
			if errors.As(err, &u) {
				return err
			}
			return fmt.Errorf("the probe socket: %w", err)
		}
		prober = probe.New(conn, m.KeyIDBytes, probe.NewSeeds(time.Hour, time.Now()), m.Now, log)
		go prober.Run(ctx)
		log.Info("probing from " + conn.LocalAddr().String())
	}
	server := api.New(m, prober, counters, clients)
	var lists *netlist.Builder
	if cfg.Netlist {
		config, err := tlsConfig(cfg.CAFile)
		if err != nil {
			return usageError{err}
		}
		lists = netlist.New(m.Store, m.Key, sourceClient(config), log, netlistSources(cfg), cfg.NetlistInterval,
			cfg.NetlistTorInterval, "opence-master/"+core.Version+" (+https://github.com/OpenCommunityEdition/opence-master-server)")
		if err := lists.Load(); err != nil {
			return fmt.Errorf("the netlist: %w", err)
		}
		server.Netlist = lists
		go lists.Run(ctx)
	}
	bot := discord.New(m, discord.Gateway(log), log)
	m.Watcher = bot
	pages, err := web.New(m, clients)
	if err != nil {
		return err
	}
	pages.Lists = server.ListLimiter()
	pages.Applying = bot
	adminPages, err := admin.New(m, clients)
	if err != nil {
		return err
	}
	adminPages.Discord = bot
	adminPages.Netlist = lists
	restarts := make(chan string, 1)
	updater.Restart = func(binary string) { restarts <- binary }
	updater.Available = bot.UpdateAvailable
	updater.Started = func(version, actor string) {
		_ = m.Store.Audit(actor, "update", "", core.Version+" to "+version)
		bot.UpdateStarted(version, actor)
	}
	updater.Failed = func(version string, err error) {
		_ = m.Store.Audit("update", "update-failed", "", version+": "+err.Error())
		bot.UpdateFailed(version, err)
	}
	bot.Updates = updater
	adminPages.Updates = updater
	bot.Start(ctx)
	go updater.Run(ctx, cfg.UpdateInterval)
	mux := http.NewServeMux()
	server.Routes(mux)
	pages.Routes(mux)
	adminPages.Routes(mux)

	if len(m.Peers) > 0 {
		syncer := &peers.Syncer{Master: m, Client: m.Notifier.Client}
		go syncer.Run(ctx, cfg.PeersInterval)
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if err := m.Store.Purge(sign.NonceWindow, 7*24*time.Hour); err != nil {
				log.Warn("purge failed", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	var listener net.Listener
	if inherited := update.Listener(); inherited != nil {
		// (the socket of the process this one replaced, by an update)
		listener, err = net.FileListener(inherited)
		inherited.Close()
	} else {
		listener, err = net.Listen("tcp", cfg.Listen)
	}
	if err != nil {
		return fmt.Errorf("MASTER_LISTEN: %w", err)
	}
	go func() {
		// (a release that served this long is the fallback of the next)
		select {
		case <-ctx.Done():
		case <-time.After(time.Minute):
			update.MarkGood(updater.Dir, core.Version)
		}
	}()
	httpServer := &http.Server{
		Handler: clients.HSTS(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	scheme := "http"
	if cfg.TLSCert != "" {
		scheme = "https"
	}
	if cfg.PublicURL == "" {
		log.Warn("no MASTER_PUBLIC_URL: the bot's messages and mails carry paths, not links")
	}
	log.Info("serving", "name", m.Name(), "url", scheme+"://"+listener.Addr().String(), "key_id", m.KeyID,
		"peers", len(m.Peers), "probe", cfg.Probe)
	// (a line a test or a panel can wait for)
	fmt.Fprintf(os.Stdout, "opence-master: listening on %s://%s, key id %s\n", scheme, listener.Addr(), m.KeyID)
	if code := adminPages.SetupCode(); code != "" {
		link := setupLink(cfg.PublicURL, scheme, listener.Addr()) + "/admin/setup?code=" + code
		log.Warn("the master is not set up: open the setup link to name it and make the admin token", "link", link)
		fmt.Fprintf(os.Stdout, "\nopence-master: not set up yet. To name this master and make its admin token, open\n"+
			"  %s\n(a new link is printed at each start until the setup is done)\n\n", link)
	}
	errs := make(chan error, 1)
	go func() {
		if cfg.TLSCert != "" {
			errs <- httpServer.ServeTLS(listener, cfg.TLSCert, cfg.TLSKey)
		} else {
			errs <- httpServer.Serve(listener)
		}
	}()
	select {
	case err := <-errs:
		return err
	case binary := <-restarts:
		return restart(binary, listener, httpServer, bot, stop, closeStore, log)
	case <-ctx.Done():
	}
	log.Info("stopping")
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}

func keygen(args []string) error {
	set := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := set.String("out", os.Getenv("MASTER_KEY"), "the key file to write (MASTER_KEY)")
	force := set.Bool("force", false, "replace an existing key file")
	keep := set.Bool("keep", false, "keep an existing key file, printing its public key")
	if _, err := parse(set, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError{errors.New("keygen --out <file>")}
	}
	if _, err := os.Stat(*out); err == nil && *keep {
		key, err := sign.LoadSeed(*out)
		if err != nil {
			return err
		}
		fmt.Printf("kept %s\n%s\n", *out, sign.Describe(key.Public().(ed25519.PublicKey)))
		return nil
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s exists; a master's key is its identity (--force replaces it)", *out)
	}
	key, err := writeKey(*out)
	if err != nil {
		return err
	}
	public := key.Public().(ed25519.PublicKey)
	fmt.Printf("wrote %s\n%s\nmasters.txt line: https://master.example.org %s\n", *out, sign.Describe(public),
		sign.PublicKeyText(public))
	return nil
}

func administer(command string, args []string) error {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	values := config.Flags(set)
	quota := set.Int("quota", 0, "the publisher's quota (approve; default MASTER_DEFAULT_QUOTA)")
	reason := set.String("reason", "", "the reason, recorded in the audit log")
	all := set.Bool("all", false, "every application, not only the pending ones")
	public := set.Bool("public", false, "export without contacts and applications")
	out := set.String("out", "", "the file to write (export; default standard output)")
	var in core.ApplicationInput
	set.StringVar(&in.Name, "display-name", "", "the publisher's name (add-application)")
	set.StringVar(&in.PublicKey, "public-key", "", "the publisher key, ed25519:<64 hex> (add-application)")
	set.IntVar(&in.Servers, "servers", 1, "servers at once (add-application)")
	set.StringVar(&in.Region, "region", "", "the region (add-application)")
	set.StringVar(&in.Note, "note", "", "a note to the approvers (add-application)")
	proofNonce := set.String("proof-nonce", "", "the nonce \"challenge\" printed (add-application)")
	proofSignature := set.String("proof-signature", "", "the key's signature of the nonce, as halo --server --sign "+
		"prints it (add-application)")
	set.StringVar(&in.DiscordID, "discord-id", "", "the applicant's Discord user id (add-application, challenge)")
	set.StringVar(&in.DiscordName, "discord-name", "", "the applicant's Discord username (add-application)")
	positional, err := parse(set, args)
	if err != nil {
		return err
	}
	need := map[string]int{"approve": 1, "deny": 1, "suspend": 1, "resume": 1, "revoke": 1, "quota": 2, "import": 1,
		"challenge": 0, "add-application": 0}
	if n, ok := need[command]; ok && len(positional) != n {
		return usageError{fmt.Errorf("%s takes %d argument(s)", command, n)}
	}
	m, closeStore, err := open(set, values, true)
	if err != nil {
		return err
	}
	defer closeStore()
	actor := "cli"
	switch command {
	case "challenge":
		fmt.Println(m.ProofNonce(strings.TrimSpace(in.DiscordID)))
	case "add-application":
		if *proofNonce != "" || *proofSignature != "" {
			in.Proof = &core.Proof{Nonce: *proofNonce, Signature: *proofSignature}
		}
		a, err := m.Apply(in, actor)
		if err != nil {
			return err
		}
		fmt.Printf("application %s: key %s, %s, proof of key %v\n", a.ID, a.KeyID, a.Status, a.ProofOK)
	case "approve":
		p, err := m.Approve(positional[0], *quota, actor)
		if err != nil {
			return err
		}
		fmt.Printf("approved %s: publisher %s\n", positional[0], p.ID)
	case "deny":
		if strings.TrimSpace(*reason) == "" {
			return usageError{errors.New("deny needs --reason")}
		}
		if err := m.Deny(positional[0], *reason, actor); err != nil {
			return err
		}
		fmt.Printf("denied %s\n", positional[0])
	case "suspend", "resume":
		status := map[string]string{"suspend": model.Suspended, "resume": model.Approved}[command]
		if err := m.SetStatus(positional[0], status, *reason, actor); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", positional[0], status)
	case "revoke":
		if sign.ValidKeyID(positional[0]) {
			if err := m.RevokeKey(positional[0], *reason, actor); err != nil {
				return err
			}
			fmt.Printf("key %s revoked\n", positional[0])
		} else {
			if err := m.SetStatus(positional[0], model.Revoked, *reason, actor); err != nil {
				return err
			}
			fmt.Printf("publisher %s revoked\n", positional[0])
		}
	case "quota":
		var n int
		if _, err := fmt.Sscan(positional[1], &n); err != nil {
			return usageError{errors.New("quota <publisher> <n>")}
		}
		if err := m.SetQuota(positional[0], n, actor); err != nil {
			return err
		}
		fmt.Printf("%s: quota %d\n", positional[0], n)
	case "list-applications":
		status := model.ApplicationPending
		if *all {
			status = ""
		}
		list, err := m.Store.Applications(status, 10000)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tNAME\tKEY ID\tSERVERS\tAPPLICANT\tPROOF\tAPPLIED")
		for _, a := range list {
			applicant := "cli"
			switch {
			case a.DiscordID != "":
				applicant = "discord:" + a.DiscordID + " " + a.Discord
			case a.Email != "":
				applicant = a.Email
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%v\t%s\n", a.ID, a.Status, a.Name, a.KeyID, a.Servers,
				applicant, a.ProofOK, view.TimeText(a.Created))
		}
		return w.Flush()
	case "list-publishers":
		states, err := m.States()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tBY\tNAME\tQUOTA\tKEYS\tORIGIN\tSINCE")
		for _, s := range states {
			var keys []string
			for _, k := range s.Keys {
				keys = append(keys, k.KeyID+":"+k.Status)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", s.Publisher.ID, s.Status, s.StatusBy,
				s.Publisher.Name, s.Quota, strings.Join(keys, ","), s.Publisher.Origin, core.Since(s.Publisher.Since))
		}
		return w.Flush()
	case "export":
		e, err := m.Store.Export(m.KeyID, *public)
		if err != nil {
			return err
		}
		var w io.Writer = os.Stdout
		if *out != "" {
			f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(e)
	case "import":
		data, err := os.ReadFile(positional[0])
		if err != nil {
			return err
		}
		var e store.Export
		if err := json.Unmarshal(data, &e); err != nil {
			return fmt.Errorf("%s: %w", positional[0], err)
		}
		if e.Format != store.ExportFormat {
			return fmt.Errorf("%s is not an opence-master export (format %q)", positional[0], e.Format)
		}
		counts, err := m.Store.Import(&e, m.KeyID)
		if err != nil {
			return err
		}
		_ = m.Store.Audit(actor, "import", positional[0], fmt.Sprintf("from master %s: %+v", e.Master, counts))
		fmt.Printf("imported: %d publishers, %d statuses, %d keys, %d applications; %d records refused\n",
			counts.Publishers, counts.Opinions, counts.Keys, counts.Applications, counts.Refused)
		if e.Master != m.KeyID {
			fmt.Printf("(an export of master %s: its records in this master's name, %s, were refused)\n", e.Master,
				m.KeyID)
		}
	}
	return nil
}

func health(args []string) error {
	set := flag.NewFlagSet("health", flag.ContinueOnError)
	listen := os.Getenv("MASTER_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8090"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return usageError{err}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	target := set.String("url", "http://"+net.JoinHostPort(host, port)+"/healthz", "the URL to check")
	if _, err := parse(set, args); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(*target)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", *target, response.StatusCode)
	}
	return nil
}

// setupLink is the master's origin for the setup link: MASTER_PUBLIC_URL,
// else the listener's address (localhost for one on every address).
func setupLink(public, scheme string, address net.Addr) string {
	if public != "" {
		return public
	}
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return scheme + "://" + address.String()
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "localhost"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// newUpdater makes the updater: it installs releases in bin/ beside the
// database.
func newUpdater(cfg *config.Config, log *slog.Logger) (*update.Updater, error) {
	text := cfg.UpdateKey
	if text == "" {
		text = update.ReleaseKey
	}
	key, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(text), "ed25519:"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("MASTER_UPDATE_KEY: an Ed25519 public key, 64 hexadecimal digits")
	}
	config, err := tlsConfig(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	// (it follows redirects: GitHub's downloads are)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}
	dir := filepath.Join(filepath.Dir(cfg.DB), "bin")
	return &update.Updater{Current: core.Version, Mode: cfg.Updates, Source: cfg.UpdateURL, Dir: dir,
		Client: client, Key: key, Log: log}, nil
}

// restart replaces the process with an installed release: the requests
// being served are finished, the database is closed, and the listening
// socket is handed over, so connections wait for the new process rather
// than being refused.
func restart(binary string, listener net.Listener, server *http.Server, bot *discord.Bot, stop func(),
	closeStore func(), log *slog.Logger) error {
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		return errors.New("the restart needs a TCP listener")
	}
	socket, err := tcp.File()
	if err != nil {
		return fmt.Errorf("the restart: the listener: %w", err)
	}
	// (the update notice says the master is updating before it goes)
	bot.Sync()
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		log.Warn("update: requests cut short by the restart", "err", err)
	}
	closeStore()
	log.Info("update: restarting", "binary", binary)
	err = update.Exec(binary, socket)
	// (only if it failed: the supervisor starts the master again, which
	// runs the installed release)
	return fmt.Errorf("the restart into %s: %w", binary, err)
}

// updateCommand installs the latest release from the command line.
func updateCommand(args []string) error {
	set := flag.NewFlagSet("update", flag.ContinueOnError)
	values := config.Flags(set)
	only := set.Bool("check", false, "tell whether a newer release is out, installing nothing")
	if _, err := parse(set, args); err != nil {
		return err
	}
	cfg, err := config.Load(values)
	if err != nil {
		return usageError{err}
	}
	updater, err := newUpdater(cfg, logger(cfg.LogLevel))
	if err != nil {
		return usageError{err}
	}
	if !update.Valid(core.Version) {
		return fmt.Errorf("this is a development build (%s): it is not updated", core.Version)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	release, err := updater.Check(ctx)
	if err != nil {
		return err
	}
	if !update.Newer(release.Version, core.Version) {
		fmt.Printf("opence-master %s is the latest release\n", core.Version)
		return nil
	}
	if *only {
		fmt.Printf("release %s is out (this is %s): %s\n", release.Version, core.Version, release.URL)
		return nil
	}
	binary, err := updater.Install(ctx, release)
	if err != nil {
		return err
	}
	fmt.Printf("installed %s as %s; the master runs it at its next start (systemctl restart opence-master)\n",
		release.Version, binary)
	return nil
}

// writeKey makes a master key and writes it to a new key file.
func writeKey(path string) (ed25519.PrivateKey, error) {
	key, err := sign.NewSeed()
	if err != nil {
		return nil, err
	}
	text := "# OpenCE master key (Ed25519 seed). Keep it secret and backed up.\n" + sign.SeedText(key) + "\n"
	return key, os.WriteFile(path, []byte(text), 0o600)
}

// firstKey makes the master key at a new master's first start: when
// MASTER_KEY is a file that does not exist and neither does the database.
// A database without its key is refused: the key is the master's identity,
// which a new one would not be (restore it from the backup).
func firstKey(cfg *config.Config, log *slog.Logger) error {
	if _, err := sign.LoadSeed(cfg.Key); err == nil || !errors.Is(err, os.ErrNotExist) {
		// (a key, or another failure, which open reports)
		return nil
	}
	if _, err := os.Stat(cfg.DB); err == nil {
		return usageError{fmt.Errorf("the master key %s is missing but the database %s exists: restore the key "+
			"from its backup (a new key would be another master)", cfg.Key, cfg.DB)}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Key), 0o700); err != nil {
		return err
	}
	key, err := writeKey(cfg.Key)
	if err != nil {
		return fmt.Errorf("the master key: %w", err)
	}
	log.Warn("made the master key for this new master: back it up, it is the master's identity", "file", cfg.Key,
		"public_key", sign.PublicKeyText(key.Public().(ed25519.PublicKey)))
	return nil
}
