# AGENTS.md

Notes for coding agents (and people) changing this repository. `README.md`
is the user documentation and has the package map ("Contents"); this file
is what a change has to keep true.

## Commands

```sh
go build ./... && go vet ./... && go test -race ./...
gofmt -l .                                              # must print nothing
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...   # CI fails on any finding
python3 -m pytest -q tests/conformance                  # the protocol, end to end
sh -n install.sh && dash -n install.sh                  # the installer is POSIX sh
docker run --rm -v "$PWD:/repo" --workdir /repo rhysd/actionlint:1.7.12   # the workflows, with shellcheck
```

Tests touch nothing beyond loopback: Discord is a fake `Client`
(`internal/discord/bot_test.go`), releases are an `httptest` server
(`internal/update/update_test.go`), the database is `:memory:`.

## The protocol is a contract

- The spec is `docs/master_protocol.md` in the game's repository
  (OpenCommunityEdition, the `halo-jonas-android` checkout), not here. A
  change to what goes over the wire changes the spec first.
- `testdata/vectors.json` is made by `go test ./internal/vectors -update`
  and a byte-identical copy lives in the game's repository; change both
  together. CI checks the file is what the code makes.
- `tests/conformance` is the test any master must pass to be official.

## Invariants

- **Secrets never reach a log, a page, the audit log or an error**: the
  admin token, the Discord token (`redact`, `discordLog`), the SMTP
  password. Tests check it; keep them checking.
- **HTTPS or loopback**: publishes, key changes, the admin pages and the
  setup refuse plain HTTP (`Clients.Of(r).Protected()`). `X-Forwarded-*`
  are believed only from `MASTER_TRUSTED_PROXIES`. In Docker, the master's
  port is published on 127.0.0.1 only (`compose.proxy.yaml`): on another
  address every client would come through the trusted gateway.
- **Updates install only what the release key signed** (`internal/update`:
  `SHA256SUMS` and its `.sig`, checked against `update.ReleaseKey`). Never
  add a way around the signature. The seed is the `RELEASE_SIGNING_KEY`
  secret and is never in the repository.
- **The master key is the master's identity**: never replaced silently. A
  key is made only for a new master (no key file and no database:
  `firstKey`).
- **Settings**: every option is in `config.Options` (an environment variable
  and a flag) and in README.md's "Options" table. What the admin pages or
  the bot set lives in the database's settings, and the environment wins
  (`FromEnv`); show it as set by the environment rather than editable.
- **Every admin action is audited** through `core` or `Store.Audit`, with
  its actor (`admin`, `cli`, `discord:<id> <name>`, `auto`).
- **Discord**: `gateway.go` alone imports discordgo; the rest uses the
  `Client` interface, so the fake can test it. No mention in a message pings
  anyone (`noMentions`). Who may do what: approvers by role, server admins
  (`Interaction.Admin`) for `/configure` and updates.
- The database schema only grows: new columns go in `store.migrations`,
  and a version's first start backs the database up (`BackupDatabase`).

## Style

- Comments are terse and say why; asides go in parentheses, as in
  `// (the code is claimed once: a second form sent with it is refused)`.
  Match the file you are in.
- Errors and user-facing text name the fix (`set MASTER_X`, `run /configure`,
  `restore the key from its backup`).
- Templates are embedded (`internal/*/templates`); a new admin page is
  added to the map in `admin.New`, with the files it includes.
- Pages work without JavaScript; the CSS is `internal/web/static/style.css`.

## Releases

`git tag vX.Y.Z && git push origin vX.Y.Z` runs `.github/workflows/release.yml`:
tests and govulncheck, the binaries (linux amd64, arm64, armv7), the signed
`SHA256SUMS`, the multi-arch image on ghcr.io, and then the GitHub release
(last: masters act on it as soon as it is out). The release carries
`install.sh`, `compose.yaml`, `compose.proxy.yaml` and the `Caddyfile`, which
the installer downloads from the latest release, so an installer change
reaches users only with a new tag. Only `vX.Y.Z` builds update themselves;
others report themselves as development builds.

CI and the release use the latest patch of Go 1.26 (`go-version: "1.26.x"`,
`check-latest`), not the `go 1.26.0` floor in `go.mod`, whose standard
library has known vulnerabilities. Actions are pinned to commit SHAs with
the version in a comment. A workflow YAML cannot parse runs nothing on its
tag, with no error but a failed run named after the file: check them with
actionlint (CI does), and mind a `: ` inside an unquoted value (a step's
name). Run it with shellcheck, as its image above has and CI's runner does:
without it, actionlint passes the `run:` scripts that CI then fails. GitHub
runs a tag's own workflow file, so a fix needs a new tag.

## The installer

`install.sh` runs as `curl ... | sh`: POSIX sh only (no bash-isms), questions
read from `/dev/tty`, each question also an option and an environment
variable, `--yes` answers everything, and a re-run keeps the earlier
choices (`$DIR/.env`) and the data. Test it against local release files
with `OPENCE_RELEASE_URL` (a directory served over HTTP holding
`compose.yaml`, `compose.proxy.yaml`, `Caddyfile` and their `SHA256SUMS`)
and a locally built `ghcr.io/opencommunityedition/opence-master-server:latest`.
