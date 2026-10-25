"""Conformance test of an OpenCE master (protocol 1), with no game data.

It starts masters on loopback with temporary databases (plain HTTP is
allowed from loopback) and drives them with the reference publisher
(opence_publisher.py), through the whole flow of the plan's 7.7:
application, a pending publish refused, approval on the command line, a
publish waiting for the probe, the probe answered, the server listed with
its exact listing bytes in a signed list, closing, the refusals (a bad
signature, a stale ts, a replayed nonce, quotas, a revoked key), and two
masters sharing an approval and a revocation.

Applicants apply with a master's Discord bot, which the test cannot reach:
it makes its applications on the master's command line instead
(`challenge` for the proof of key's nonce, then `add-application`), and
checks that the earlier HTTP endpoint answers 410 applications_by_discord.

The master under test is OPENCE_MASTER_BIN (default: this repository's,
built with go). Another implementation passes if it takes the same
command line (keygen --out, serve, challenge, add-application, approve,
deny, suspend, resume, revoke) and MASTER_* variables.

    python3 -m pytest -q tests/conformance
"""

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import opence_publisher as op  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADMIN_TOKEN = "conformance-" + "a" * 40


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def binary(tmp_path_factory):
    given = os.environ.get("OPENCE_MASTER_BIN")
    if given:
        return given
    if not shutil.which("go"):
        pytest.skip("no OPENCE_MASTER_BIN and no go to build one")
    out = str(tmp_path_factory.mktemp("bin") / "opence-master")
    subprocess.run(["go", "build", "-o", out, "./cmd/opence-master"], cwd=ROOT, check=True,
                   env=dict(os.environ, CGO_ENABLED="0"))
    return out


class Master:
    """A master process on loopback."""

    def __init__(self, binary, directory, name):
        self.binary = binary
        self.directory = directory
        self.name = name
        self.port = free_port()
        self.url = "http://127.0.0.1:%d" % self.port
        self.key_path = os.path.join(directory, "master.key")
        self.log_path = os.path.join(directory, "master.log")
        self.process = None
        out = subprocess.run([binary, "keygen", "--out", self.key_path], capture_output=True, text=True, check=True)
        self.public = op.parse_public_key(re.search(r"ed25519:([0-9a-f]{64})", out.stdout).group(1))
        self.key_id = op.key_id(self.public)

    def env(self, peers="", **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith("MASTER_")}
        env.update({
            "MASTER_NAME": self.name, "MASTER_CONTACT": "conformance@example.org",
            "MASTER_DB": os.path.join(self.directory, "master.db"), "MASTER_KEY": self.key_path,
            "MASTER_LISTEN": "127.0.0.1:%d" % self.port, "MASTER_PUBLIC_URL": self.url,
            "MASTER_PROBE_LISTEN": "127.0.0.1:0", "MASTER_ADMIN_TOKEN": ADMIN_TOKEN,
            "MASTER_PUBLISH_MIN_INTERVAL": "1s", "MASTER_APPLICATIONS_PER_DAY": "100",
            "MASTER_APPLICATIONS_PER_HOUR": "1000", "MASTER_APPLICATIONS_PER_KEY": "100",
            "MASTER_PEERS": peers, "MASTER_PEERS_INTERVAL": "1s", "MASTER_LOG_LEVEL": "info",
        })
        env.update(extra)
        return env

    def start(self, peers="", **extra):
        self._env = self.env(peers, **extra)
        self.log = open(self.log_path, "w")
        self.process = subprocess.Popen([self.binary, "serve"], env=self._env, stdout=subprocess.PIPE,
                                        stderr=self.log, text=True)
        ready = threading.Event()

        def wait():
            for line in self.process.stdout:
                if "listening on" in line:
                    ready.set()

        threading.Thread(target=wait, daemon=True).start()
        if not ready.wait(15):
            self.stop()
            raise RuntimeError("the master did not start: " + open(self.log_path).read())
        return self

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if getattr(self, "log", None):
            self.log.close()

    def cli(self, *args, check=True):
        result = subprocess.run([self.binary, *args], env=self._env, capture_output=True, text=True, timeout=30)
        if check:
            assert result.returncode == 0, (args, result.stdout, result.stderr)
            return result.stdout
        return result

    def add_application(self, seed, name, servers=1, region="", note="", proof=True):
        """An application on the command line (an applicant's goes through the master's Discord bot), with
        a proof of key (the nonce of `challenge`, signed) unless proof is False: its id, key id, status and
        whether its proof was verified."""
        args = ["add-application", "--display-name", name, "--public-key", op.public_key_text(op.public_key(seed)),
                "--servers", str(servers), "--region", region, "--note", note]
        if proof:
            nonce = self.cli("challenge").strip()
            assert re.fullmatch(r"opence-apply-[0-9]+-[0-9a-f]{16}", nonce), nonce
            args += ["--proof-nonce", nonce, "--proof-signature", op.proof_of_key(seed, nonce)]
        out = self.cli(*args)
        match = re.search(r"application (a_[a-z0-9]+): key ([0-9a-f]{16}), (\w+), proof of key (true|false)", out)
        assert match, out
        return {"id": match.group(1), "key_id": match.group(2), "status": match.group(3),
                "proof": match.group(4) == "true"}

    def request(self, method, path, body=None, seed=None, **kwargs):
        kwargs.setdefault("master_key_id", self.key_id)
        return op.request(self.url, method, path, body, seed, **kwargs)

    def json(self, method, path, body=None, seed=None, **kwargs):
        status, headers, data = self.request(method, path, body, seed, **kwargs)
        return status, json.loads(data or b"{}")

    def list(self, query=""):
        status, headers, data = self.request("GET", "/v1/servers" + query)
        assert status == 200, data
        return op.verify_list(data, headers, self.public), headers, data


@pytest.fixture(scope="module")
def master(binary, tmp_path_factory):
    m = Master(binary, str(tmp_path_factory.mktemp("master")), "Conformance master").start()
    yield m
    m.stop()


@pytest.fixture(scope="module")
def two_masters(binary, tmp_path_factory):
    a = Master(binary, str(tmp_path_factory.mktemp("a")), "Master A")
    b = Master(binary, str(tmp_path_factory.mktemp("b")), "Master B")
    a.start(peers="%s %s" % (b.url, op.public_key_text(b.public)))
    b.start(peers="%s %s" % (a.url, op.public_key_text(a.public)))
    yield a, b
    a.stop()
    b.stop()


def code(answer):
    return answer.get("error", {}).get("code")


def approved_publisher(master, quota=None, name="Conformance operator"):
    seed = op.new_seed()
    answer = master.add_application(seed, name, servers=2)
    assert answer["status"] == "pending", answer
    args = ["approve", answer["id"]] + (["--quota", str(quota)] if quota else [])
    out = master.cli(*args)
    publisher_id = re.search(r"publisher (p_[a-z0-9]+)", out).group(1)
    return seed, publisher_id


def until(predicate, timeout=12, step=0.25):
    deadline = time.time() + timeout
    while True:
        value = predicate()
        if value or time.time() > deadline:
            return value
        time.sleep(step)


# ---------------------------------------------------------------- the vectors

def test_reference_publisher_matches_the_vectors():
    with open(os.path.join(ROOT, "testdata", "vectors.json")) as f:
        v = json.load(f)
    for name in ("publisher", "master", "host"):
        key = v[name]
        public = op.public_key(bytes.fromhex(key["seed"]))
        assert op.public_key_text(public) == key["public_key"]
        assert op.key_id(public) == key["key_id"]
        assert op.key_id_bytes(public).hex() == key["key_id_bytes"]
    assert v["server_id_input"] == v["publisher"]["key_id"] + v["instance"]
    assert op.server_id(v["publisher"]["key_id"], v["instance"]) == v["server_id"]
    seed = bytes.fromhex(v["publisher"]["seed"])
    for request in (v["publish_request"], v["me_request"]):
        body = request["body"].encode()
        assert op.body_hash(body) == request["body_sha256"]
        assert request["master_key_id"] == v["master"]["key_id"]
        assert request["canonical"].split("\n")[:2] == ["OpenCE-Master-v1", v["master"]["key_id"]]
        assert op.canonical(request["master_key_id"], request["method"], request["path"], request["ts"],
                            request["nonce"], body) == request["canonical"]
        assert op.authorization(seed, request["master_key_id"], request["method"], request["path"], body,
                                int(request["ts"]),
                                request["nonce"]) == request["authorization"]
    assert v["me_request"]["body_sha256"] == hashlib.sha256(b"").hexdigest()
    probe = v["probe"]
    master_id, nonce = bytes.fromhex(probe["master_key_id"]), bytes.fromhex(probe["nonce"])
    assert op.probe_packet(master_id, nonce).hex() == probe["packet"]
    assert len(bytes.fromhex(probe["packet"])) == 35
    assert op.probe_answer(seed, master_id, nonce).hex() == probe["answer"]
    assert len(bytes.fromhex(probe["answer"])) == 103
    for listing in v["listings"]:
        data = bytes.fromhex(listing["bytes"])
        assert base64.b64decode(listing["base64"]) == data
        if not listing["valid"]:
            with pytest.raises(ValueError):
                op.read_listing(data)
            continue
        token = bytes.fromhex(listing["token"]) if "token" in listing else None
        sealed = bytes.fromhex(listing["sealed_token"]) if "sealed_token" in listing else None
        made = op.make_listing(bytes.fromhex(listing["host_seed"]), listing["name"], listing["map"],
                               listing["gametype"], players=listing["players"], max_players=listing["max_players"],
                               engine=listing["engine"], kind=listing["kind"], flags=listing["flags"],
                               sequence=listing["sequence"], unix_time=listing["time"], token=token, sealed=sealed,
                               network_version=listing["network_version"])
        assert made == data, listing["description"]
        read = op.read_listing(data)
        assert (read["name"], read["players"], read["kind"], read["flags"]) == (
            listing["name"], listing["players"], listing["kind"], listing["flags"])
    host = op.public_key(bytes.fromhex(v["host"]["seed"]))
    assert op.seal_token(b"\x01" * 32, host, bytes(range(0xA0, 0xB0)), b"\x02" * 24).hex() == \
        v["listings"][1]["sealed_token"]
    signed = v["list"]
    headers = {"Signature": signed["signature_header"], "Signature-Key": signed["signature_key_header"],
               "Signature-Time": signed["signature_time_header"]}
    master_public = op.parse_public_key(v["master"]["public_key"])
    op.verify_list(signed["body"].encode(), headers, master_public, now=int(signed["signature_time_header"]))
    assert op.verify(op.public_key(seed), v["proof_nonce"].encode(), bytes.fromhex(v["proof_signature_hex"]))


def test_pure_python_ed25519_agrees():
    seed = bytes(range(32))
    message = b"OpenCE"
    assert op.pure_public_key(seed) == op.public_key(seed)
    assert op.pure_sign(seed, message) == op.sign(seed, message)
    assert op.pure_verify(op.public_key(seed), message, op.sign(seed, message))


# ---------------------------------------------------------------- one master

def test_pages_health_and_metrics(master):
    status, answer = master.json("GET", "/healthz")
    assert status == 200 and answer["ok"] is True
    status, answer = master.json("GET", "/v1/master")
    assert status == 200 and answer["master"]["key_id"] == master.key_id and answer["protocol"] == 1
    for path in ("/", "/apply", "/admin/login"):
        status, headers, data = master.request("GET", path)
        assert status == 200 and b"<html" in data, path
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    status, _, data = master.request("GET", "/metrics")
    text = data.decode()
    for name in ("master_servers", "master_publishers", "master_publishes_total", "master_probes_total",
                 "master_list_requests_total", "master_build_info"):
        assert name in text, name


def test_the_whole_flow(master):
    seed = op.new_seed()
    responder = op.ProbeResponder(seed, [op.key_id_bytes(master.public)])
    try:
        # the application, with a proof of key
        answer = master.add_application(seed, "Milenko's servers", servers=2, region="eu", note="two CTF servers")
        assert answer["status"] == "pending" and answer["proof"] is True, answer
        assert answer["key_id"] == op.key_id(op.public_key(seed))
        application = answer["id"]
        # the key's own record: an application, pending
        status, me = op.Publisher(master.url, master.key_id, seed, "main", 2302).me()
        assert status == 200 and me["publisher"] is None and me["application"]["id"] == application, me

        publisher = op.Publisher(master.url, master.key_id, seed, "main", responder.port, region="eu", variant="CTF")
        host = op.new_seed()
        listing = op.make_listing(host, "Conformance CTF", "bloodgulch", "CTF", players=5, max_players=16,
                                  engine=1, flags=op.LISTING_OPEN | op.LISTING_TEAMS, sequence=1)

        # pending until approved
        status, answer, _ = publisher.publish(listing)
        assert status == 403 and code(answer) == "publisher_pending", answer
        out = master.cli("approve", application)
        assert "publisher p_" in out

        # the first publish waits for the probe; the next is listed
        status, answer, _ = publisher.publish(listing, players=99)
        assert status == 202 and answer["listed"] is False and answer["probe"] == "pending", answer
        assert answer["server_id"] == publisher.server_id
        assert any("players" in w for w in answer.get("warnings", [])), answer
        assert responder.event.wait(10), "the master did not probe"

        def listed():
            time.sleep(1.05)
            status, answer, _ = publisher.publish(listing)
            return (status, answer) if status == 200 and answer["listed"] else None

        result = until(listed, 10, 0)
        assert result, "not listed after the probe was answered"
        status, answer = result
        assert answer["probe"] == "ok" and answer["reachable"] is True and answer["interval"] == 30
        assert answer["ttl"] == 90 and answer["observed_address"] == "127.0.0.1"
        assert abs(answer["master_time"] - time.time()) < 30

        # the list carries the exact listing bytes, signed by the master
        body, headers, raw = master.list("?network_version=%d&dedicated=1" % op.NETWORK_VERSION)
        entries = [e for e in body["servers"] if e["id"] == publisher.server_id]
        assert len(entries) == 1, body
        entry = entries[0]
        assert base64.b64decode(entry["listing"]) == listing
        op.read_listing(base64.b64decode(entry["listing"]))
        assert entry["players"] == 5 and entry["max_players"] == 16 and entry["teams"] is True
        assert entry["name"] == "Conformance CTF" and entry["map"] == "bloodgulch" and entry["dedicated"] is True
        assert entry["publisher"]["name"] == "Milenko's servers" and entry["region"] == "eu"
        assert entry["reachable"] is True and "address" not in entry
        assert headers.get("Cache-Control") == "public, max-age=5"
        assert headers.get("Access-Control-Allow-Origin") == "*"
        etag = headers.get("ETag")
        assert etag
        status, _, _ = master.request("GET", "/v1/servers?network_version=%d&dedicated=1" % op.NETWORK_VERSION,
                                      headers={"If-None-Match": etag})
        assert status == 304
        status, headers2, zipped = master.request("GET", "/v1/servers?network_version=%d&dedicated=1" %
                                                  op.NETWORK_VERSION, headers={"Accept-Encoding": "gzip"})
        assert headers2.get("Content-Encoding") == "gzip"
        op.verify_list(gzip.decompress(zipped), headers2, master.public)

        # one server, a publisher's profile, the publisher's own record
        status, headers, data = master.request("GET", "/v1/servers/" + publisher.server_id)
        assert status == 200 and op.verify_list(data, headers, master.public)["server"]["id"] == publisher.server_id
        status, me = publisher.me()
        assert status == 200 and me["publisher"]["status"] == "approved"
        assert [s["id"] for s in me["publisher"]["servers"]] == [publisher.server_id]
        status, profile = master.json("GET", "/v1/publishers/" + me["publisher"]["id"])
        assert status == 200 and profile["servers"] == 1 and profile["name"] == "Milenko's servers"
        assert "email" not in profile

        # closed: unlisted at once
        time.sleep(1.05)
        tombstone = op.make_listing(host, "Conformance CTF", "bloodgulch", "CTF", flags=op.LISTING_CLOSED, sequence=2)
        status, answer, _ = publisher.publish(tombstone, closed=True)
        assert status == 200 and answer["closed"] is True, answer
        body, _, _ = master.list()
        assert publisher.server_id not in [e["id"] for e in body["servers"]]
    finally:
        responder.close()


def test_refusals(master):
    seed, _ = approved_publisher(master, quota=1)
    publisher = op.Publisher(master.url, master.key_id, seed, "refusals", 2302)
    listing = op.make_listing(op.new_seed(), "Refusals", "prisoner", "Slayer", players=1)
    body = json.dumps(publisher.body(listing)).encode()
    path = "/v1/servers/" + publisher.server_id

    # a bad signature
    header = op.authorization(seed, master.key_id, "PUT", path, body)
    signature = bytearray(base64.b64decode(header.rsplit("sig=", 1)[1]))
    signature[0] ^= 1
    bad = header.rsplit("sig=", 1)[0] + "sig=" + base64.b64encode(bytes(signature)).decode()
    status, answer = master.json("PUT", path, body, raw_authorization=bad)
    assert status == 401 and code(answer) == "bad_signature", answer
    # a stale ts, told the master's time
    stale = op.authorization(seed, master.key_id, "PUT", path, body, ts=int(time.time()) - 400)
    status, answer = master.json("PUT", path, body, raw_authorization=stale)
    assert status == 401 and code(answer) == "clock" and abs(answer["master_time"] - time.time()) < 30, answer
    # a replayed nonce
    header = op.authorization(seed, master.key_id, "PUT", path, body)
    status, answer = master.json("PUT", path, body, raw_authorization=header)
    assert status in (200, 202), answer
    status, answer = master.json("PUT", path, body, raw_authorization=header)
    assert status == 401 and code(answer) == "replay", answer
    # a server id that is not the key's and the instance's
    status, answer = master.json("PUT", "/v1/servers/0123456789abcdef", body, seed)
    assert status == 400 and code(answer) == "server_id", answer
    # a listing whose signature fails
    forged = bytearray(listing)
    forged[-1] ^= 1
    status, answer = master.json("PUT", path, publisher.body(bytes(forged)), seed)
    assert status == 400 and code(answer) == "listing", answer
    # a field of the wrong type
    status, answer = master.json("PUT", path, publisher.body(listing, tunnel_port="2302"), seed)
    assert status == 400 and code(answer) == "schema" and answer["error"]["field"] == "tunnel_port", answer
    # a body over 16 KB
    status, _, _ = master.request("PUT", path, publisher.body(listing, padding="x" * 17000), seed)
    assert status == 413
    # a key no one approved
    stranger = op.Publisher(master.url, master.key_id, op.new_seed(), "x", 2302)
    status, answer, _ = stranger.publish(listing)
    assert status == 403 and code(answer) == "unknown_key", answer
    # over the quota
    time.sleep(1.05)
    second = op.Publisher(master.url, master.key_id, seed, "second", 2303)
    status, answer, _ = second.publish(listing)
    assert status == 403 and code(answer) == "quota_exceeded", answer
    # suspended, then resumed
    status, me = publisher.me()
    publisher_id = me["publisher"]["id"]
    master.cli("suspend", publisher_id, "--reason", "conformance")
    status, answer, _ = publisher.publish(listing)
    assert status == 403 and code(answer) == "publisher_suspended", answer
    master.cli("resume", publisher_id)
    time.sleep(1.05)
    status, answer, _ = publisher.publish(listing)
    assert status in (200, 202), answer
    # a revoked key
    master.cli("revoke", publisher.key_id, "--reason", "conformance")
    status, answer, _ = publisher.publish(listing)
    assert status == 403 and code(answer) == "key_revoked", answer


def test_requests_are_bound_to_the_master(master):
    seed, _ = approved_publisher(master)
    publisher = op.Publisher(master.url, master.key_id, seed, "bound", 2302)
    listing = op.make_listing(op.new_seed(), "Bound", "prisoner", "Slayer")
    body = json.dumps(publisher.body(listing)).encode()
    path = "/v1/servers/" + publisher.server_id
    # signed for another master: refused here
    other = op.authorization(seed, "0123456789abcdef", "PUT", path, body)
    status, answer = master.json("PUT", path, body, raw_authorization=other)
    assert status == 401 and code(answer) == "bad_signature", answer
    status, answer = master.json("PUT", path, body, raw_authorization=op.authorization(seed, master.key_id, "PUT",
                                                                                         path, body))
    assert status in (200, 202), answer
    # another publisher's copy of the listing's bytes is refused while it is live
    thief_seed, _ = approved_publisher(master, name="Copying operator")
    thief = op.Publisher(master.url, master.key_id, thief_seed, "copy", 2302)
    status, answer, _ = thief.publish(listing)
    assert status == 403 and code(answer) == "listing_taken", answer


def test_applications_by_discord_only(master):
    seed = op.new_seed()
    body = json.dumps({"name": "Form operator", "email": "form@example.org",
                       "public_key": op.public_key_text(op.public_key(seed)), "servers": 1}).encode()
    # the HTTP endpoints of the earlier web form are gone: applications are made with the Discord bot
    for method, path in (("POST", "/v1/applications"), ("GET", "/v1/applications/challenge")):
        status, answer = master.json(method, path, body if method == "POST" else None)
        assert status == 410 and code(answer) == "applications_by_discord", (path, answer)
    status, _, page = master.request("GET", "/apply")
    assert status == 200 and b"/apply" in page and b"Discord" in page and b"<form" not in page
    status, _, _ = master.request("POST", "/apply", b"name=x",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status in (404, 405), status
    # the operator's command line: a proof of key is required by default
    result = master.cli("add-application", "--display-name", "Unproven operator", "--public-key",
                        op.public_key_text(op.public_key(seed)), check=False)
    assert result.returncode != 0 and "proof" in result.stderr, result
    # and a nonce bound to a Discord user is that user's only
    nonce = master.cli("challenge", "--discord-id", "123456789012345678").strip()
    result = master.cli("add-application", "--display-name", "Other operator", "--public-key",
                        op.public_key_text(op.public_key(seed)), "--proof-nonce", nonce, "--proof-signature",
                        op.proof_of_key(seed, nonce), check=False)
    assert result.returncode != 0 and "nonce" in result.stderr, result
    answer = master.add_application(seed, "Bound operator")
    assert answer["proof"] is True


def test_publish_rate_limit(master):
    seed, _ = approved_publisher(master)
    publisher = op.Publisher(master.url, master.key_id, seed, "rate", 2302)
    listing = op.make_listing(op.new_seed(), "Rate", "prisoner", "Slayer")
    statuses = [publisher.publish(listing)[0] for _ in range(4)]
    assert 429 in statuses, statuses
    status, headers, _ = op.request(master.url, "PUT", "/v1/servers/" + publisher.server_id,
                                    publisher.body(listing), seed, master_key_id=master.key_id)
    if status == 429:
        assert headers.get("Retry-After")


def test_unanswered_probe(master):
    seed, _ = approved_publisher(master)
    port = free_port()  # nothing answers there
    publisher = op.Publisher(master.url, master.key_id, seed, "silent", port)
    listing = op.make_listing(op.new_seed(), "Silent", "prisoner", "Slayer")
    status, answer, _ = publisher.publish(listing)
    assert status == 202 and answer["probe"] == "pending", answer
    time.sleep(7)
    status, answer, _ = publisher.publish(listing)
    assert status == 200 and answer["listed"] is False and answer["probe"] == "failed", answer
    assert answer["probe_address"] == "127.0.0.1:%d" % port and "UDP port" in answer["reason"]


def test_peer_endpoint_refuses_strangers(master):
    status, answer = master.json("GET", "/v1/publishers?since=0", seed=op.new_seed())
    assert status == 403 and code(answer) == "not_a_peer", answer


# ---------------------------------------------------------------- two masters

def test_two_masters_share_an_approval_and_a_revocation(two_masters):
    a, b = two_masters
    seed = op.new_seed()
    responder = op.ProbeResponder(seed, [op.key_id_bytes(a.public), op.key_id_bytes(b.public)])
    try:
        answer = a.add_application(seed, "Shared operator")
        a.cli("approve", answer["id"])
        on_b = op.Publisher(b.url, b.key_id, seed, "shared", responder.port)
        listing = op.make_listing(op.new_seed(), "Shared", "bloodgulch", "CTF", players=2)

        def accepted():
            time.sleep(1.05)
            status, answer, _ = on_b.publish(listing)
            return (status, answer) if status in (200, 202) else None

        assert until(accepted, 15, 0), "b never took a's approval"

        def listed_on_b():
            time.sleep(1.05)
            status, answer, _ = on_b.publish(listing)
            return status == 200 and answer["listed"]

        assert until(listed_on_b, 15, 0), "not listed on b"
        body, _, _ = b.list()
        assert on_b.server_id in [e["id"] for e in body["servers"]]

        # a's revocation reaches b: refused there, and gone from b's list
        a.cli("revoke", on_b.key_id, "--reason", "stolen")

        def revoked_on_b():
            time.sleep(1.05)
            status, answer, _ = on_b.publish(listing)
            return status == 403 and code(answer) == "key_revoked"

        assert until(revoked_on_b, 15, 0), "b did not learn of the revocation"

        def gone():
            body, _, _ = b.list()
            return on_b.server_id not in [e["id"] for e in body["servers"]]

        assert until(gone, 10), "b still lists a revoked key's server"
    finally:
        responder.close()


def test_two_masters_share_a_suspension(two_masters):
    a, b = two_masters
    seed, publisher_id = approved_publisher(a, name="Suspended operator")
    on_a = op.Publisher(a.url, a.key_id, seed, "suspend", 2302)
    listing = op.make_listing(op.new_seed(), "Suspend", "prisoner", "Slayer")

    def b_knows():
        status, answer = b.json("GET", "/v1/publishers/" + publisher_id)
        return status == 200

    assert until(b_knows, 15), "b never imported the publisher"
    b.cli("suspend", publisher_id, "--reason", "spam on b")

    def suspended_on_a():
        time.sleep(1.05)
        status, answer, _ = on_a.publish(listing)
        return status == 403 and code(answer) == "publisher_suspended"

    assert until(suspended_on_a, 15, 0), "a did not take b's suspension"
    b.cli("resume", publisher_id)

    def resumed_on_a():
        time.sleep(1.05)
        status, answer, _ = on_a.publish(listing)
        return status in (200, 202)

    assert until(resumed_on_a, 15, 0), "a did not take b's resumption"
