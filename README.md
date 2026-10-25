# opence-master

`opence-master` is a master server for [OpenCE](https://github.com/OpenCommunityEdition),
the port of Halo: Combat Evolved: it lists the dedicated servers of
approved operators. An operator applies once, with the public half of an
Ed25519 key, through the master's Discord bot (`/apply`); once an approver
approves the application (on Discord, or on the admin pages), every publish
their servers make is signed with that key, so the master knows who is behind
each listed server. Before a server is listed, the master probes its UDP
port and the server answers with a signature of the same key.

The master does not carry game traffic. Each list entry holds the game's
own host-signed listing (the bytes the game publishes to the signalling
brokers), so the game's join path is unchanged, and the list itself is
signed with the master's key, which the game pins in its `masters.txt`.

It implements **protocol version 1**, specified in the game's repository in
`docs/master_protocol.md`.
The protocol is the contract; this program is one implementation of it.
[`testdata/vectors.json`](testdata/vectors.json) has fixed keys and the ids,
signatures, probes, listings and signed bodies derived from them, and
[`tests/conformance`](tests/conformance) is the test any master must pass to
be an official one.

One static Go binary (no CGO), one SQLite file. Licence: AGPL-3.0-or-later
(`LICENSE`): a master is a network service, so its users are owed its source.

## Installing

On a Linux server (a small VPS is enough) with a domain whose DNS record
points at it:

```sh
curl -fsSL https://github.com/OpenCommunityEdition/opence-master-server/releases/latest/download/install.sh | sh
```

It asks how HTTPS reaches the master, and for its domain; it installs
Docker if it is missing (it asks first), sets the master up in
`/opt/opence-master`, starts it, and prints a setup link: open it to name
the master and get its admin token. For HTTPS, either:

1. **Caddy in Docker** (the default) gets the certificate itself; it needs
   ports 80 and 443.
2. **Your own reverse proxy** on the machine (nginx, Caddy, ...): the
   master listens on `127.0.0.1:8090` only (`--port` changes it), and the
   installer prints the proxy's configuration (Caddy's and nginx's, in
   `/opt/opence-master/reverse-proxy.txt`). The proxy must send
   `X-Forwarded-Proto`, `X-Forwarded-For` and `X-Forwarded-Host`: without
   them the master refuses its admin pages and the servers' publishes.

Then set up the Discord bot on the admin pages (["The Discord
bot"](#the-discord-bot)). The master updates itself from then on
(["Updating"](#updating)).

To read the script before running it: download it with
`curl -fsSLO <the same URL>`, then `sh install.sh`. To ask nothing, give the
answers: `sh -s -- --domain master1.example.org --yes`, with `--proxy
external --port 8090` for your own proxy (`--dir` installs elsewhere than
`/opt/opence-master`). Running it again repairs an install, moves it to a
new domain or switches its proxy, and keeps its data and choices. Without
Docker, see ["Running a master"](#running-a-master) (systemd).

## Contents

| Path | What |
| --- | --- |
| `cmd/opence-master` | The command: `serve` and the administration commands |
| `internal/sign` | Keys, key ids, server ids, the `OpenCE-Ed25519` request signature, signed bodies |
| `internal/listing` | The game's listing: reading it and checking the host's signature |
| `internal/probe` | The UDP reachability probe: packets, stateless nonces, the probe state machine |
| `internal/api` | The `/v1` endpoints, `/healthz`, `/metrics` |
| `internal/core` | Who a key is, approvals, moderation, which servers are listed |
| `internal/model` | Records, and the rules that combine several masters' words on a publisher |
| `internal/peers` | Approval sharing between masters |
| `internal/store` | The SQLite database |
| `internal/discord` | The Discord bot: `/apply`, the applications' log channel and its Approve and Deny buttons, the applicants' direct messages (`gateway.go` alone talks to Discord) |
| `internal/web`, `internal/admin` | The public pages (the list, how to apply) and the admin pages (with the bot's settings) |
| `internal/update` | The updates: the release check, the signed download, the restart into it, the database's backups |
| `cmd/release-sign` | Signs a release's `SHA256SUMS` with the release key (the release workflow) |
| `internal/vectors` | Makes `testdata/vectors.json` (`go test ./internal/vectors -update`) |
| `tests/conformance` | `test_master_protocol.py` and the reference publisher `opence_publisher.py` |
| `install.sh` | The installer: Docker, Compose with Caddy, the setup link |
| `Dockerfile`, `compose.yaml`, `deploy/` | The image, Compose with Caddy for TLS, the systemd unit |

## Building and testing

```sh
go build ./cmd/opence-master                 # Go 1.26 or newer
go vet ./... && go test ./...
python3 -m pytest -q tests/conformance       # needs pytest; builds the binary with go
```

The conformance test starts masters on loopback with temporary databases
and drives them with the reference publisher; it needs no game data and
contacts nothing beyond loopback. The reference publisher uses Python's
`cryptography` package when it is installed and pure-Python Ed25519
otherwise (`OPENCE_PUBLISHER_PURE=1` forces the latter).

## Running a master

A small VPS is enough: a few hundred servers publishing every 30 seconds
and a few thousand players' lists are a few requests a second, and the list
is cached for 5 seconds. The master needs a domain, a certificate (a
reverse proxy gets one), outbound UDP for the probe, and a Discord server
for its bot, where operators apply and approvers decide (the bot connects
out to Discord: it needs no public URL of its own).

```sh
opence-master keygen --out /var/lib/opence-master/master.key   # prints the public key for masters.txt
MASTER_PUBLIC_URL=https://master1.example.org MASTER_DB=/var/lib/opence-master/master.db \
MASTER_KEY=/var/lib/opence-master/master.key MASTER_TRUSTED_PROXIES=127.0.0.1 \
opence-master serve --listen 127.0.0.1:8090
```

with Caddy in front: `master1.example.org { reverse_proxy 127.0.0.1:8090 }`.

**First launch.** A new master has no name and no admin token: it prints a
setup link to its log (and to standard output), such as
`https://master1.example.org/admin/setup?code=510ec9b0...`, again at each
start until the setup is done. Open it to give the master its name (shown
in its list, its pages and the bot's messages) and, optionally, an admin
contact (an e-mail address or a URL, shown on its pages and told to denied
applicants). The setup then shows the admin token once: keep it, you log
in to the admin pages with it (the master keeps only its hash). The link
is good once. **Settings** on the admin pages changes the name and the
contact later. `MASTER_NAME`, `MASTER_CONTACT` and `MASTER_ADMIN_TOKEN`
still set them instead, and win; with `MASTER_ADMIN_TOKEN` there is no setup
link, and the admin pages ask for the name after the login.

A master refuses
publishes, key changes and the admin pages over plain HTTP, except from
loopback directly; behind a proxy it believes `X-Forwarded-Proto`,
`X-Forwarded-For` and `X-Forwarded-Host` only from the addresses in
`MASTER_TRUSTED_PROXIES`. Answers to requests that came over TLS carry
`Strict-Transport-Security`. The database file is made readable by its
owner only (mode 0600).

**Loopback as a trusted proxy.** `deploy/opence-master.service` sets
`MASTER_TRUSTED_PROXIES=127.0.0.1,::1`, for a proxy on the same machine.
Two consequences: a request made directly on the machine (`curl
http://127.0.0.1:8090/admin/`, a script, a health check) is taken as the
proxy's, so it is plain HTTP from the proxy and refused `tls_required`
unless it sends `X-Forwarded-Proto: https` (`/healthz` and the list need no
TLS); and any process on the machine can send any `X-Forwarded-For`, so it
can pose as any client address to the rate limits. Run nothing untrusted
on a master's machine, or put the proxy on its own address (a container
network, as `compose.yaml` does) and trust only that one.

- **systemd**: `deploy/opence-master.service` (`DynamicUser=yes`,
  `StateDirectory=opence-master`; the key is made at the first start and
  its public half is in the journal). The settings go in
  `/etc/opence-master/env` (`deploy/master.env.example`).
- **Docker**: `install.sh` (["Installing"](#installing)) does it; by hand,
  `compose.yaml` runs the master and Caddy:
  `echo MASTER_DOMAIN=master1.example.org > .env`, `echo
  MASTER_PUBLIC_URL=https://master1.example.org > master.env`, then
  `docker compose up -d`. The master makes its key at its first start (a
  new database without a key file); back up the `master-data` volume. The
  image is distroless, runs as a non-root user, and keeps everything in
  `/data`.

### The Discord bot

Operators apply with the master's Discord bot, and the approvers decide in
a Discord channel (or on the admin pages). To set it up:

1. In the [Developer Portal](https://discord.com/developers/applications),
   make a New Application (its name is the bot's), then on its **Bot** page
   press **Reset Token** and copy the token. The bot needs no privileged
   gateway intent: leave Presence, Server Members and Message Content off
   (the members' roles come with each button press).
2. In your Discord server, make a channel for the applications that only
   the approvers (and the bot) can see, and a role for the approvers. With
   Developer Mode on (User Settings, Advanced), right-click the server to
   copy its id.
3. On the master's admin pages, **Discord**: paste the token, the server
   id and, optionally, a public invite to the server, which the `/apply`
   page shows. Save: the bot connects, and the page shows its state (off,
   connecting, connected as its name, or the error, such as a refused
   token). The token is kept in the database (readable by its owner only),
   never shown again and never logged; **Clear the token** turns the bot
   off. In a container, `MASTER_DISCORD_TOKEN`, `MASTER_DISCORD_GUILD` and
   `MASTER_DISCORD_INVITE` set them instead; what the environment sets wins,
   and the page shows it as set by the environment.
4. Add the bot to the server with **Invite to server**, beside **Save and
   connect**:
   `https://discord.com/oauth2/authorize?client_id=<the application id>&scope=bot+applications.commands&permissions=19456&guild_id=<the server id>&disable_guild_select=true`:
   the scopes `bot` and `applications.commands`, and the permissions View
   Channel, Send Messages and Embed Links (19456), which it needs in the
   log channel only. Then press **Connect again** if it connected before
   it was in the server.
5. In Discord, a server admin (Administrator or Manage Server) runs
   `/configure` (or `/config`), which only they see, and chooses the log
   channel and the approver roles (10 at most) in its menus. The bot takes
   a channel once it could post to it, and each choice is written to the
   audit log; the admin page shows them. `MASTER_DISCORD_CHANNEL` and
   `MASTER_DISCORD_APPROVER_ROLES` (ids; the roles separated by commas)
   set them instead, and `/configure` then leaves them as they are. A new
   server id clears them.

The bot registers `/apply`, `/configure` and `/config` in that server only. It answers an applicant
alone with a nonce for the proof of key (good 24 hours, for that Discord
user's applications only) and a button that opens the form: a display
name, the public key, the proof (what `halo --server --sign <nonce>`
prints), the number of servers at once and a region (one input, `2 eu`:
a form has 5 inputs at most), and a note. A refused form is answered with
the reason and a button to try again, filled in with what was sent. A
Discord user has one pending application at a time and
`MASTER_APPLICATIONS_PER_DAY` a day. Each application is posted to the log
channel: its name, the applicant (a mention), the key id, the servers and
region, whether it has a proof of key, the other applications from the same
Discord user or for the same key, and a link to its admin page, with
**Approve** (with the default quota, as the admin page's) and **Deny**
(which asks for the reason). Only members of an approver role may press
them. Once an application is decided, on Discord, on the admin pages or on
the command line, its message shows the outcome, who decided and when, and
loses its buttons (a decision made by another process, such as the command
line, within 15 seconds), and the bot tells the applicant by a direct
message (when their settings allow it). An application is decided once:
of two decisions at once (two approvers, or Discord and the admin page)
the second is refused, and a denied application stays denied (an Approve
button left on an old message is refused). A denial's reason is 300
characters at most. An application Discord refuses to take in the channel
(the channel gone, or out of the bot's reach) is not tried again: it is on
the admin pages, and the bot's admin page shows the error. Past
`MASTER_APPLICATIONS_PER_HOUR` applications in an hour, the channel is
alerted once and the next ones that hour are not posted one by one (they
are on the admin pages). Every decision is in the audit log, with its
actor: `discord:<user id> <username>`, `admin` or `cli`.

The bot talks to Discord over its gateway (an outgoing WebSocket to
`gateway.discord.gg`) and its HTTPS API (`discord.com`), through
[discordgo](https://github.com/bwmarrin/discordgo).

### Options

Every option is an environment variable and a flag of `serve` (the flag
wins); `opence-master serve -h` lists them (without the values of the
secrets: the admin token, the SMTP password and the bot's token). Every
limit by address counts an
IPv6 address by its /64; the limits' memory (65,536 addresses each) holds at
most 4,096 /64s of one /48, and makes room by forgetting the addresses that
are least restricted, never one a flood drained while a fuller one is held.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MASTER_NAME` | (the setup's) | The master's name, in its lists and pages |
| `MASTER_CONTACT` | (the setup's) | Who answers for the master, optional: an e-mail address or a URL |
| `MASTER_DATA_POLICY` | addresses kept 7 days, never served, no data sold | The policy shown on the pages |
| `MASTER_PUBLIC_URL` | | The public HTTPS origin, for the links in the bot's messages and in mails |
| `MASTER_DB` | `master.db` | The SQLite file |
| `MASTER_KEY` | `master.key` | The master key: a key file, or its 64 hexadecimal digits |
| `MASTER_ADMIN_TOKEN` | (the setup's) | The admin pages' token, 32 characters or more; set, it replaces the one the setup made |
| `MASTER_DISCORD_TOKEN` | (the admin pages') | The Discord bot's token; set, it replaces the admin pages' |
| `MASTER_DISCORD_GUILD` | (the admin pages') | The Discord server (guild) id where the bot's `/apply` is |
| `MASTER_DISCORD_CHANNEL` | (`/configure`'s) | The channel id where the bot posts the applications |
| `MASTER_DISCORD_APPROVER_ROLES` | (`/configure`'s) | The role ids, separated by commas, whose members approve and deny |
| `MASTER_DISCORD_INVITE` | (the admin pages') | An invite to the Discord server, shown on the `/apply` page |
| `MASTER_NOTIFY_WEBHOOK` | | A Discord-compatible webhook told of new applications, besides the bot's log channel |
| `MASTER_LISTEN` | `127.0.0.1:8090` | The HTTP listener |
| `MASTER_TLS_CERT`, `MASTER_TLS_KEY` | | Serve HTTPS directly instead of behind a proxy |
| `MASTER_TRUSTED_PROXIES` | | Proxies (addresses or CIDRs) whose `X-Forwarded-*` headers are believed |
| `MASTER_PEERS` | | Peer masters, `"<url> ed25519:<64 hex>"` separated by commas, or a `masters.txt` file |
| `MASTER_PEERS_TRUST` | `all` | Whose approvals are imported: `all` the peers, `none`, or a list of key ids |
| `MASTER_PEERS_INTERVAL` | `60s` | How often the peers' approvals are fetched |
| `MASTER_PROBE` | `true` | Probe servers' UDP ports before listing them |
| `MASTER_PROBE_LISTEN` | `[::]:0` | The probe socket: `[::]:0` is dual-stack (IPv6 and IPv4 servers), falling back to IPv4 only where the machine has no IPv6; an IPv4 address probes IPv4 servers only |
| `MASTER_LIST_UNREACHABLE` | `false` | List servers whose probe failed, as `reachable: false` |
| `MASTER_SERVE_ADDRESSES` | `false` | Serve the address of servers that publish one (`server.master_publish_address`) |
| `MASTER_CA_FILE` | | Extra certificate authorities (PEM) for peers, the webhook and SMTP. Peers and the webhook are fetched without following redirects |
| `MASTER_SMTP_ADDR`, `MASTER_SMTP_USER`, `MASTER_SMTP_PASSWORD`, `MASTER_MAIL_FROM` | | Mail, to the operators of the earlier web form's applications when they are decided (`MASTER_SMTP_ADDR` is `host:port`); without an SMTP server, mails are written to the log whole. The bot's applicants are told by Discord |
| `MASTER_SMTP_TLS` | `auto` | TLS to the SMTP server, always: `auto` (implicit TLS on port 465, else STARTTLS), `starttls` (a server that does not offer it is refused, nothing is sent), `tls` (implicit TLS on any port), or `none` (only for an SMTP server on loopback). Certificates are checked against the system's authorities and `MASTER_CA_FILE` |
| `MASTER_DEFAULT_QUOTA` | `4` | Servers at once for a new publisher (1 to 1000) |
| `MASTER_PUBLISH_MIN_INTERVAL` | `5s` | The least time between one server's publishes (a burst of 2) |
| `MASTER_LIST_RATE` | `60` | Requests a minute per address for the list, one server, a publisher's page, the list page and `/metrics` together |
| `MASTER_APPLICATIONS_PER_DAY` | `3` | Applications a day per Discord user, who has one pending at a time (checked first) |
| `MASTER_APPLICATIONS_PER_KEY` | `3` | Applications a day per publisher key (checked next) |
| `MASTER_APPLICATIONS_PER_HOUR` | `100` | An hour's applications in all past which the admins are alerted once (the log channel, the webhook and the log), and the next ones that hour are logged rather than posted one by one; applications without a proof of key are refused once as many of them came in an hour. One with a proof is never refused for it |
| `MASTER_REQUIRE_PROOF` | `true` | Refuse applications without a proof of key; with `false` they are taken and flagged as unproven to the admins |
| `MASTER_LOG_ADDRESSES` | `false` | Write servers' addresses in the log |
| `MASTER_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `MASTER_UPDATES` | `notify` | `notify` (the admins update with a button), `auto` (a new release is installed at once) or `off` |
| `MASTER_UPDATE_INTERVAL` | `6h` | How often the releases are checked |
| `MASTER_UPDATE_URL` | the project's | The latest release on GitHub's API (a fork's) |
| `MASTER_UPDATE_KEY` | the project's | The release key's public key, 64 hex digits (a fork's) |

### Administration

The admin pages are at `/admin/` (log in with the setup's admin token, or `MASTER_ADMIN_TOKEN`; a
script may send `Authorization: Bearer <token>` instead): applications
(with their Discord applicant, proof of key, flagged when missing, and the
other applications from the same Discord user or for the same key; the
earlier web form's show their e-mail address and its verification),
approved or denied there as on Discord, publishers (each master's word on them,
their keys, and for one approved from a Discord application, its applicant's
Discord user id, which a change of username does not change; it is never
shared with peers nor in `export --public`), servers (`hidden`: listed to nobody, the operator told why at
each publish; `trusted`: listed without a probe, for a server behind a NAT
the probe cannot reach; and the disputed listings: publishes refused with
`listing_taken`, and host keys taken over from a server replaying an old
listing, which an admin settles by hiding the copying server or suspending
its publisher), the peers, the Discord bot's settings and state, and the
audit log. Every action, from the pages, Discord or the command line, is
written to the audit log.

```sh
opence-master list-applications [--all]
opence-master challenge [--discord-id <id>]              # a nonce for a proof of key
opence-master add-application --display-name <name> --public-key ed25519:<hex> [--servers n] \
    [--region r] [--note t] [--proof-nonce <nonce> --proof-signature <hex>] [--discord-id <id> --discord-name <name>]
opence-master approve <application> [--quota 4]
opence-master deny <application> --reason "..."
opence-master list-publishers
opence-master suspend <publisher> [--reason "..."]     # publishes refused, servers unlisted at once
opence-master resume <publisher>
opence-master revoke <publisher | key id> [--reason "..."]   # for good
opence-master quota <publisher> <n>
```

The commands take the same `MASTER_DB` and `MASTER_KEY` as `serve` and may
run while it does. `add-application` is for an admin who takes an
application by hand, and for tests: it applies the same rules as the bot
(a proof of key unless `MASTER_REQUIRE_PROOF` is off: `challenge` prints
the nonce to sign, bound to `--discord-id` when given), and the running
master posts it to the log channel.

### Backups

Copy `master.db` (with `sqlite3 master.db ".backup copy.db"`, or while the
master is stopped) and keep `master.key` with it: the key is the master's
identity, pinned in every game's `masters.txt`, and the records it signed
are its own only under the same key. `opence-master export > publishers.json`
writes every publisher, each master's word on them, their keys and the
applications; `opence-master import publishers.json` merges such a file
(a newer word replaces an older one). `export --public` leaves out contacts
and applications, for handing the records to another master. An import
takes the records in this master's own name only from this master's own
export (the file's `master` is its key id): in another master's file they
are refused, since this master would share them with its peers as its own
word. Records with an unknown status, a malformed key, a key that is not
its key id's, or a key another publisher holds here are refused too; the
command says how many.

### Updating

A master keeps itself up to date. Every 6 hours (`MASTER_UPDATE_INTERVAL`)
it checks the project's latest release; when a newer one is out, it says so
on every admin page and posts a notice to the bot's applications log
channel with **Update now** (for the Discord server's admins:
Administrator or Manage Server) and a link to the release notes.
**Update now**, or **Update** on the admin pages' **Settings**, then:

1. downloads the release's binary for the machine and its `SHA256SUMS`,
   and checks the signature of `SHA256SUMS` by the project's release key,
   which is built into the master (nothing else is installed), the binary's
   SHA-256, and that it runs;
2. installs it in `bin/` beside the database (`/data/bin` in the
   container, `/var/lib/opence-master/bin` with systemd), since the
   program's own file may be read-only;
3. finishes the requests being served and restarts into it in place, the
   listening socket handed over, so no connection is refused meanwhile;
4. the new version backs the database up (`master.db.before-<version>`,
   the 3 newest kept) before its first start changes it, and the notice
   says it is updated, who started it and when.

At each start, the master runs the newest installed release if it is newer
than its own program (so pulling a newer image works too), and goes back
to the last one that ran well if a release fails to start three times.
`MASTER_UPDATES=auto` installs a release as soon as it is out;
`MASTER_UPDATES=off` checks nothing. Development builds (not a `vX.Y.Z`
tag) never update.

Other ways:

- **Docker**: `docker compose pull && docker compose up -d` (the image is
  `ghcr.io/opencommunityedition/opence-master-server`, tagged `latest`,
  `1.2.0` and `1.2`).
- **systemd**: `sudo opence-master update --db /var/lib/opence-master/master.db && sudo systemctl
  restart opence-master` (`--check` only says whether a release is out).

To go back after an update: stop the master, copy
`master.db.before-<version>` (and its `-wal`, if any) over `master.db`,
remove `bin/`, and start the older program.

**Making a release** (maintainers): `git tag v1.2.0 && git push origin
v1.2.0`. The release workflow tests, builds the binaries (linux amd64,
arm64 and armv7), signs `SHA256SUMS` with the `RELEASE_SIGNING_KEY` secret
(the seed `go run ./cmd/release-sign keygen` printed; its public half is
`internal/update/key.go`), pushes the image, and publishes the release
last. The workflow refuses a key whose signature the masters would refuse.

### What is kept, and for how long

| What | Kept |
| --- | --- |
| Request nonces | 600 seconds |
| A closed server's record | an hour after it closed |
| A server's record not published again | 24 hours (unless an admin hid or trusted it) |
| Server records per publisher | its quota and 16; past that, the oldest records not live go first |
| Servers' addresses, and the web form's applicants' | 7 days |
| A web form's application never verified | 7 days |
| A denied application | 30 days after the denial |
| The audit log | its newest 100,000 entries |

## Applying as an operator

1. On the server, `halo --server --keygen` writes `publisher.key` beside
   `config.toml` and prints its public key (`ed25519:<64 hex>`) and key id.
   The private key never leaves the server.
2. In the master's Discord server (its `/apply` page links to it), type
   `/apply`. The bot answers you alone with a nonce: run
   `halo --server --sign <nonce>` on the server (required unless the
   master's `MASTER_REQUIRE_PROOF` is off).
3. Press **Fill in the application**: a display name (shown beside your
   servers), the public key, what `--sign` printed, how many servers at
   once and a region (`2 eu`), and a note. The server may publish
   meanwhile: it is told `publisher_pending` until an approver approves the
   application, and is listed at its next publish after that. The bot tells
   you of the decision by a direct message.

The master's website takes no applications: `POST /v1/applications`
answers `410 applications_by_discord`. The official masters share
approvals, so one application is enough.

## Becoming an official master

The game ships the official masters in `port/assets/network/masters.txt`
(`https://<origin> ed25519:<64 hex>` per line) and the web page's
`masters.json`. To add one, open a pull request on the game's repository
adding its line to both, with in the description:

- the admin contact and the data policy (addresses kept 7 days for probes
  and abuse handling and never served; no sale of data);
- that the master runs `opence-master` or another implementation that
  passes `tests/conformance`, over HTTPS with a valid certificate;
- its key, and that it agrees to the shared approval rules (peers import
  each other's approvals; a suspension or revocation anywhere wins
  everywhere).

The maintainers run the conformance test against the candidate and check
that `/healthz`, `/metrics` and `/apply` answer, and that its Discord
bot takes applications. Each official master
lists the others in `MASTER_PEERS`. Removing a master is the reverse pull
request.

## Approval sharing

Each master keeps every master's latest word on a publisher apart (its
"opinion": a status, a quota, a time) and takes the most restrictive of the
trusted opinions as the publisher's status: one master's suspension
suspends the publisher everywhere, and only that master's resumption lifts
it. A revoked key or publisher stays revoked. A master fetches each peer's
`GET /v1/publishers?since=` every `MASTER_PEERS_INTERVAL`, signed with its
own key, and checks the answer's signature with the peer's key; it shares
only the records it holds an opinion of its own on (the publishers it
approved or moderated, the keys it added or revoked), never a peer's word
as its own. `MASTER_PEERS_TRUST` stops a peer's words counting.

## Dependencies

| Module | Licence | What uses it |
| --- | --- | --- |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | BSD-3-Clause | The database (`internal/store`), SQLite without CGO |
| [github.com/bwmarrin/discordgo](https://github.com/bwmarrin/discordgo) v0.29.0 | BSD-3-Clause | The Discord bot's connection (`internal/discord/gateway.go` only) |
| [github.com/gorilla/websocket](https://github.com/gorilla/websocket) v1.5.3 | BSD-2-Clause | discordgo's gateway WebSocket (and its close codes, in `gateway.go`) |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | BSD-3-Clause | discordgo's (its voice code, which the bot does not use) |

Each is compatible with the AGPL 3.0; `go.sum` pins their checksums.

## Licence

AGPL-3.0-or-later. Copyright the OpenCE contributors.
