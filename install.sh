#!/bin/sh
# Installs an OpenCE master server with Docker, behind Caddy (which gets its
# HTTPS certificate):
#
#   curl -fsSL https://github.com/OpenCommunityEdition/opence-master-server/releases/latest/download/install.sh | sh
#
# It asks for the master's domain (whose DNS points at this machine),
# installs Docker if it is missing (with your consent), writes compose.yaml,
# the Caddyfile and the settings to /opt/opence-master, starts the master,
# and prints the setup link that names it. Run it again to repair or move an
# install: the data (the master-data volume) and the settings are kept.
#
# Options (or the environment variables beside them):
#   --domain <name>   OPENCE_DOMAIN         the master's domain
#   --dir <path>      OPENCE_DIR            where it goes (/opt/opence-master)
#   --yes             OPENCE_YES=1          no questions: install Docker if
#                                           it is missing
set -eu

REPO="OpenCommunityEdition/opence-master-server"
BASE="${OPENCE_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
DIR="${OPENCE_DIR:-/opt/opence-master}"
DOMAIN="${OPENCE_DOMAIN:-}"
YES="${OPENCE_YES:-}"

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
fail() {
	printf '\nopence-master install: %s\n' "$*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--domain) [ $# -ge 2 ] || fail "--domain needs a name"; DOMAIN="$2"; shift 2 ;;
	--domain=*) DOMAIN="${1#--domain=}"; shift ;;
	--dir) [ $# -ge 2 ] || fail "--dir needs a path"; DIR="$2"; shift 2 ;;
	--dir=*) DIR="${1#--dir=}"; shift ;;
	-y | --yes) YES=1; shift ;;
	-h | --help) sed -n '2,20p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) fail "unknown option $1 (--help lists them)" ;;
	esac
done

# ask reads an answer from the terminal (the script itself may be standard
# input, through a pipe); with no terminal, the answer is empty.
ask() {
	printf '%s ' "$1"
	answer=""
	if [ -z "$YES" ] && [ -r /dev/tty ]; then
		read -r answer </dev/tty || answer=""
	fi
}

# ---------- what it needs

[ "$(uname -s)" = Linux ] || fail "this installer is for Linux (README.md tells of the other ways)"
parent="$DIR"
while [ ! -d "$parent" ]; do parent="$(dirname "$parent")"; done
if [ "$(id -u)" -eq 0 ]; then
	SUDO=""
elif [ -w "$parent" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	# (Docker and the directory are this user's: no root needed)
	SUDO=""
elif command -v sudo >/dev/null 2>&1; then
	SUDO="sudo"
	say "Some steps need root: sudo may ask for your password."
else
	fail "run it as root (or install sudo)"
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 3 "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	fail "curl or wget is needed"
fi

step "Docker"
if ! command -v docker >/dev/null 2>&1; then
	if [ -n "$YES" ]; then
		answer=y
	else
		ask "Docker is not installed. Install it with Docker's own script (https://get.docker.com)? [Y/n]"
	fi
	case "$answer" in
	"" | y | Y | yes) ;;
	*) fail "Docker is needed: https://docs.docker.com/engine/install/" ;;
	esac
	if [ -n "$YES" ] || [ -r /dev/tty ]; then :; else fail "no terminal to ask on: run it with --yes"; fi
	tmp_docker="$(mktemp)"
	fetch https://get.docker.com "$tmp_docker"
	$SUDO sh "$tmp_docker"
	rm -f "$tmp_docker"
fi
$SUDO docker info >/dev/null 2>&1 || fail "Docker is installed but not running: start it (systemctl start docker)"
$SUDO docker compose version >/dev/null 2>&1 ||
	fail "Docker Compose is needed (the docker-compose-plugin package): https://docs.docker.com/compose/install/"
say "$($SUDO docker --version), $($SUDO docker compose version --short 2>/dev/null || echo compose)"

# ---------- the domain

if [ -z "$DOMAIN" ] && [ -f "$DIR/.env" ]; then
	DOMAIN="$(sed -n 's/^MASTER_DOMAIN=//p' "$DIR/.env" | head -n 1)"
	[ -n "$DOMAIN" ] && say "Keeping the domain $DOMAIN (--domain changes it)."
fi
while [ -z "$DOMAIN" ]; do
	[ -r /dev/tty ] || fail "no terminal to ask on: give the domain with --domain master1.example.org"
	ask "The master's domain (its DNS record points at this machine), such as master1.example.org:"
	DOMAIN="$answer"
done
DOMAIN="$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z' | sed 's#^https\{0,1\}://##; s#/.*##')"
case "$DOMAIN" in
*[!a-z0-9.-]* | .* | *. | *..* | "") fail "\"$DOMAIN\" is not a domain name" ;;
*.*) ;;
*) fail "\"$DOMAIN\" is not a full domain name (master1.example.org)" ;;
esac

if command -v getent >/dev/null 2>&1; then
	if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
		say "Warning: $DOMAIN has no DNS record yet. Caddy gets the certificate once it points here."
	fi
fi
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -Eq '[:.](80|443)[[:space:]]'; then
	if ! $SUDO docker compose --project-directory "$DIR" ps 2>/dev/null | grep -q caddy; then
		say "Warning: something already listens on port 80 or 443; Caddy needs both (stop that web server)."
	fi
fi

# ---------- the files

step "Files in $DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in compose.yaml Caddyfile SHA256SUMS; do
	fetch "$BASE/$f" "$tmp/$f" || fail "$BASE/$f could not be downloaded"
done
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmp" && grep -E '  (compose\.yaml|Caddyfile)$' SHA256SUMS | sha256sum -c --status) ||
		fail "the downloaded files are not the release's (SHA256SUMS)"
fi
$SUDO mkdir -p "$DIR/deploy"
$SUDO install -m 644 "$tmp/compose.yaml" "$DIR/compose.yaml"
$SUDO install -m 644 "$tmp/Caddyfile" "$DIR/deploy/Caddyfile"
printf 'MASTER_DOMAIN=%s\n' "$DOMAIN" >"$tmp/.env"
$SUDO install -m 644 "$tmp/.env" "$DIR/.env"
if $SUDO test -f "$DIR/master.env"; then
	# (kept, with the domain's URL)
	$SUDO sed -i "s#^MASTER_PUBLIC_URL=.*#MASTER_PUBLIC_URL=https://$DOMAIN#" "$DIR/master.env"
	say "Kept the settings in $DIR/master.env."
else
	cat >"$tmp/master.env" <<EOF
# The master's settings (every option: README.md, "Options"). The name, the
# contact and the admin token are made by the setup link; the Discord bot is
# set up on the admin pages.
MASTER_PUBLIC_URL=https://$DOMAIN
# updates: notify (the admins update with a button), auto, or off
#MASTER_UPDATES=notify
EOF
	$SUDO install -m 600 "$tmp/master.env" "$DIR/master.env"
fi
say "Wrote compose.yaml, deploy/Caddyfile, .env and master.env."

# ---------- start

step "Starting the master and Caddy"
cd "$DIR"
if ! $SUDO docker compose pull --quiet; then
	$SUDO docker image inspect ghcr.io/opencommunityedition/opence-master-server:latest >/dev/null 2>&1 ||
		fail "the image could not be downloaded (ghcr.io/opencommunityedition/opence-master-server)"
	say "Warning: the images were not updated; using the ones already here."
fi
# (recreated: a repair runs the settings just written, and the log below is
# this start's)
$SUDO docker compose up -d --remove-orphans --force-recreate

step "Waiting for the master"
link=""
ready=""
i=0
while [ $i -lt 60 ]; do
	since="$($SUDO docker inspect -f '{{.State.StartedAt}}' "$($SUDO docker compose ps -q master)" 2>/dev/null || true)"
	logs="$($SUDO docker compose logs --no-color ${since:+--since "$since"} master 2>/dev/null || true)"
	if printf '%s' "$logs" | grep -q "listening on"; then
		ready=1
		link="$(printf '%s\n' "$logs" | grep -o 'https\{0,1\}://[^ "]*/admin/setup?code=[0-9a-f]*' | tail -n 1)"
		[ -n "$link" ] && break
		# (set up already: no link; a moment for the line to come)
		[ $i -ge 3 ] && break
	fi
	i=$((i + 1))
	sleep 2
done
[ -n "$ready" ] || fail "the master did not start: ${SUDO:+$SUDO }docker compose --project-directory $DIR logs master"

key="$(printf '%s\n' "$logs" | grep -o 'public_key=ed25519:[0-9a-f]*' | tail -n 1 | sed 's/^public_key=//')"

say ""
say "The OpenCE master runs at https://$DOMAIN"
if [ -n "$link" ]; then
	say ""
	say "Open this link to name the master and make its admin token (it is good once):"
	say ""
	say "    $link"
	say ""
	say "Caddy may take a minute to get the certificate; reload if the page does not open yet."
else
	say "It is set up already: the admin pages are at https://$DOMAIN/admin/"
fi
[ -n "$key" ] && say "" && say "Its public key, for the game's masters.txt: $key"
run="${SUDO:+$SUDO }"
say ""
say "In $DIR:"
say "  ${run}docker compose logs -f master     the log"
say "  ${run}docker compose pull && ${run}docker compose up -d   update (the admin pages and the"
say "                                            Discord bot's notice do it with a button too)"
say "  ${run}docker compose down               stop (the data stays in the master-data volume)"
say "Back up the master-data volume: it holds the database and the master key, the master's identity."
