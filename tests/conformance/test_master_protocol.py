"""Conformance test of an OpenCE master (protocol 1), with no game data.

It starts masters on loopback with temporary databases (plain HTTP is
allowed from loopback) and drives them with the reference publisher
(opence_publisher.py), through the whole flow of the plan's 7.7:
application, a pending publish refused, approval on the command line, a
publish waiting for the probe, the probe answered, the server listed with
its exact listing bytes in a signed list, closing, the refusals (a bad
signature, a stale ts, a replayed nonce, quotas, a revoked key), and two
masters sharing an approval and a revocation. It also checks the signed
netlist (a master built from sources on loopback) and the player's pass (a
link made on the command line, `add-link`, since Discord's OAuth2 is beyond
a test's reach; `revoke-link` for a revocation).

Applicants apply with a master's Discord bot, which the test cannot reach:
it makes its applications on the master's command line instead
(`challenge` for the proof of key's nonce, then `add-application`), and
checks that the earlier HTTP endpoint answers 410 applications_by_discord.

The master under test is OPENCE_MASTER_BIN (default: this repository's,
built with go). Another implementation passes if it takes the same
command line (keygen --out, serve, challenge, add-application, approve,
deny, suspend, resume, revoke, add-link, revoke-link) and MASTER_* variables.

    python3 -m pytest -q tests/conformance
"""

import base64
import gzip
import hashlib
import hmac
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

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
            # (the netlist's sources are on the internet: a test master builds from loopback ones, or none)
            "MASTER_NETLIST": "off",
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


def test_player_pass_and_netlist_vectors():
    with open(os.path.join(ROOT, "testdata", "vectors.json")) as f:
        v = json.load(f)
    master_public = op.parse_public_key(v["master"]["public_key"])
    seed = bytes.fromhex(v["player"]["seed"])
    public = op.public_key(seed)
    assert op.public_key_text(public) == v["player"]["public_key"]
    assert op.key_id(public) == v["player"]["key_id"] == v["player"]["key_id_bytes"]
    for name, label in (("link", op.LINK_LABEL), ("pass_request", op.PASS_GET_LABEL)):
        q = v[name]
        assert q["master_key_id"] == v["master"]["key_id"]
        assert op.player_signed_text(label, q["master_key_id"], public, q["ts"]) == q["signed_text"]
        assert op.player_query(seed, label, q["master_key_id"], int(q["ts"])) == q["query"]
        assert op.verify(public, q["signed_text"].encode(), bytes.fromhex(q["sig"]))
    assert op.link_code(public, v["link"]["ts"]) == v["link"]["code"]
    p = v["pass"]
    data = bytes.fromhex(p["bytes"])
    read = op.read_pass(data, master_public)
    assert (read["flags"], read["player"].hex(), str(read["discord_id"]), read["discord_name"], read["issued"],
            read["expires"]) == (p["flags"], p["player_public_key"], p["discord_id"], p["discord_name"], p["issued"],
                                 p["expires"])
    assert p["expires"] - p["issued"] == 72 * 3600 and p["master_key_id"] == v["master"]["key_id"]
    assert bytes.fromhex(p["signed_message"]) == op.PASS_LABEL + data[:106]
    assert bytes.fromhex(p["signature"]) == data[106:]
    for refused in v["passes_refused"]:
        with pytest.raises(ValueError):
            op.read_pass(bytes.fromhex(refused["bytes"]), master_public)
    proof = v["pass_proof"]
    secret = bytes.fromhex(proof["session_secret"])
    binding = hmac.new(secret, op.BINDING_LABEL, hashlib.sha256).digest()
    assert binding.hex() == proof["binding"] and proof["lan_binding"] == "00" * 32
    for binding, message, signature in ((binding, proof["message"], proof["proof"]),
                                        (bytes(32), proof["lan_message"], proof["lan_proof"])):
        assert op.proof_message(data, binding).hex() == message
        assert op.sign(seed, bytes.fromhex(message)).hex() == signature
    n = v["netlist"]
    body = bytes.fromhex(n["body"])
    headers = {"Signature": n["signature_header"], "Signature-Key": v["master"]["key_id"],
               "Signature-Time": str(n["generated"])}
    netlist = op.verify_netlist(body, headers, master_public)
    assert netlist["serial"] == n["serial"] and netlist["generated"] == n["generated"]
    assert netlist["ranges"] == [(op.address_number(a), op.address_number(b)) for a, b in n["ranges"]]
    assert base64.b64decode(n["signature_header"][8:]).hex() == n["signature"]
    assert n["etag"] == '"%s"' % hashlib.sha256(body).hexdigest()[:16]
    for refused in n["refused"]:
        with pytest.raises(ValueError):
            op.read_netlist(bytes.fromhex(refused["body"]))


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


def test_longest_listing(master):
    # a password game with every name at its length: 268 bytes, read and taken; a byte more is refused
    host = op.new_seed()
    sealed = op.seal_token(b"\x01" * 32, op.public_key(host), os.urandom(16))
    longest = op.make_listing(host, "n" * 32, "m" * 32, "g" * 24, players=16, max_players=16, kind=0x81,
                              flags=op.LISTING_OPEN | op.LISTING_PASSWORD, sealed=sealed)
    assert len(longest) == op.MAXIMUM_LISTING_SIZE == 268
    read = op.read_listing(longest)
    assert (read["name"], read["map"], read["gametype"], read["sealed"]) == ("n" * 32, "m" * 32, "g" * 24, sealed)
    shortest = op.make_listing(host, "", "", "", flags=op.LISTING_OPEN)
    assert len(shortest) == op.MINIMUM_LISTING_SIZE == 140
    op.read_listing(shortest)
    for bad in (longest + b"\x00", shortest[:-1]):
        with pytest.raises(ValueError):
            op.read_listing(bad)
    seed, _ = approved_publisher(master, name="Longest listing")
    publisher = op.Publisher(master.url, master.key_id, seed, "longest", 2302)
    status, answer, _ = publisher.publish(longest)
    assert status in (200, 202), answer
    time.sleep(1.05)
    status, answer, _ = publisher.publish(longest + b"\x00")
    assert status == 400 and code(answer) == "listing", answer


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


# ---------------------------------------------------------------- the netlist

class Sources:
    """The netlist's sources, on loopback: X4BNet's ASN lists and built lists, iptoasn's table, the Tor
    exits (fixtures of a few ranges each)."""

    FILES = {
        "/datacenter/ASN.txt": b"AS64500 # a hosting network\n",
        "/vpn/ASN.txt": b"AS64501 # a VPN provider\n",
        "/ip2asn-v4.tsv.gz": gzip.compress(b"1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET\n"
                                           b"1.2.3.0\t1.2.3.255\t64500\tGB\tHOSTING\n"
                                           b"7.7.7.0\t7.7.7.255\t64999\tUS\tNOT LISTED\n"
                                           b"45.0.0.0\t45.15.255.255\t64501\tNL\tVPN\n"),
        "/output/vpn/ipv4.txt": b"185.220.100.0/22\n10.0.0.0/8\n",
        "/output/datacenter/ipv4.txt": b"5.6.7.8/32\n",
        "/torbulkexitlist": b"5.6.7.9\n198.51.100.7\n",
    }

    def __init__(self):
        files = self.FILES

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = files.get(urllib.parse.urlsplit(self.path).path)
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                self.wfile.write(body or b"")

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def env(self):
        return {"MASTER_NETLIST": "on",
                "MASTER_NETLIST_ASN_URLS": self.url + "/datacenter/ASN.txt," + self.url + "/vpn/ASN.txt",
                "MASTER_NETLIST_IPTOASN_URL": self.url + "/ip2asn-v4.tsv.gz",
                "MASTER_NETLIST_LIST_URLS": self.url + "/output/vpn/ipv4.txt," + self.url +
                "/output/datacenter/ipv4.txt",
                "MASTER_NETLIST_TOR_URL": self.url + "/torbulkexitlist"}

    def close(self):
        self.server.shutdown()


@pytest.fixture(scope="module")
def netlist_master(binary, tmp_path_factory):
    sources = Sources()
    m = Master(binary, str(tmp_path_factory.mktemp("netlist")), "Netlist master").start(**sources.env())
    yield m
    m.stop()
    sources.close()


def test_netlist_unavailable(master):
    # a master with MASTER_NETLIST=off serves none
    status, headers, data = master.request("GET", "/v1/netlist")
    answer = json.loads(data)
    assert status == 503 and code(answer) == "netlist_unavailable" and answer["ok"] is False, answer
    assert abs(answer["master_time"] - time.time()) < 30


def test_netlist(netlist_master):
    m = netlist_master

    def built():
        status, headers, data = m.request("GET", "/v1/netlist")
        return (headers, data) if status == 200 else None

    result = until(built, 20)
    assert result, "no netlist built: " + open(m.log_path).read()
    headers, body = result
    netlist = op.verify_netlist(body, headers, m.public)
    assert abs(netlist["generated"] - time.time()) < 60 and netlist["serial"] >= 1
    # AS64500 and AS64501 expanded with iptoasn, AS13335 (the master's own by default), the built lists
    # (10.0.0.0/8 is not global), and the Tor exits (198.51.100.7 is not global; 5.6.7.9 merges with 5.6.7.8)
    want = [("1.1.1.0", "1.1.1.255"), ("1.2.3.0", "1.2.3.255"), ("5.6.7.8", "5.6.7.9"),
            ("45.0.0.0", "45.15.255.255"), ("185.220.100.0", "185.220.103.255")]
    assert netlist["ranges"] == [(op.address_number(a), op.address_number(b)) for a, b in want], netlist
    assert len(body) == 32 + 8 * len(want)
    assert headers.get("Content-Type") == "application/octet-stream"
    assert headers.get("Cache-Control") == "public, max-age=300"
    assert headers.get("Access-Control-Allow-Origin") == "*"
    etag = headers.get("ETag")
    assert etag == '"%s"' % hashlib.sha256(body).hexdigest()[:16]
    status, _, _ = m.request("GET", "/v1/netlist", headers={"If-None-Match": etag})
    assert status == 304
    status, zipped_headers, zipped = m.request("GET", "/v1/netlist", headers={"Accept-Encoding": "gzip"})
    assert status == 200 and zipped_headers.get("Content-Encoding") == "gzip"
    assert gzip.decompress(zipped) == body
    op.verify_netlist(gzip.decompress(zipped), zipped_headers, m.public)


# ---------------------------------------------------------------- the player's pass

def test_pass(master):
    seed = op.new_seed()
    public = op.public_key(seed)

    def ask(ts=None, key_seed=seed, label=op.PASS_GET_LABEL, master_key_id=None):
        query = op.player_query(key_seed, label, master_key_id or master.key_id, ts)
        status, headers, data = master.request("GET", "/v1/pass?" + query)
        assert headers.get("Access-Control-Allow-Origin") == "*" and headers.get("Cache-Control") == "no-store"
        return status, headers, data

    status, _, data = ask()
    assert status == 404 and code(json.loads(data)) == "not_linked", data
    # linked on the command line (players link with Discord, on /link)
    out = master.cli("add-link", op.public_key_text(public), "80351110224678912", "nelly")
    assert op.key_id(public) in out
    status, headers, data = ask()
    assert status == 200 and headers.get("Content-Type") == "application/octet-stream", data
    p = op.read_pass(data, master.public)
    assert p["player"] == public and p["discord_id"] == 80351110224678912 and p["discord_name"] == "nelly"
    assert abs(p["issued"] - time.time()) < 30 and p["expires"] - p["issued"] == 72 * 3600
    # refusals: a bad signature (another master's, another label's, malformed), a stale ts
    status, _, data = ask(master_key_id="0123456789abcdef")
    assert status == 401 and code(json.loads(data)) == "bad_signature", data
    status, _, data = ask(label=op.LINK_LABEL)
    assert status == 401 and code(json.loads(data)) == "bad_signature", data
    status, _, data = master.request("GET", "/v1/pass?key=%s&ts=%d&sig=00" % (public.hex(), time.time()))
    assert status == 401 and code(json.loads(data)) == "bad_signature", data
    status, _, data = ask(ts=int(time.time()) - 400)
    answer = json.loads(data)
    assert status == 401 and code(answer) == "clock" and abs(answer["master_time"] - time.time()) < 30, answer
    # revoked: the reason in the message
    master.cli("revoke-link", "80351110224678912", "conformance revocation")
    status, _, data = ask()
    answer = json.loads(data)
    assert status == 403 and code(answer) == "link_revoked", answer
    assert answer["error"]["message"] == "conformance revocation"


def test_link_pages(master):
    # the link page takes the game's signed query; this master has no Discord client secret, so it says
    # linking is not set up and names the fix
    seed = op.new_seed()
    status, headers, data = master.request("GET", "/link?" + op.player_query(seed, op.LINK_LABEL, master.key_id))
    assert status == 503 and b"MASTER_DISCORD_CLIENT_SECRET" in data and b"/link/callback" in data
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    for path in ("/privacy", "/link/manage"):
        status, _, data = master.request("GET", path)
        assert status == 200 and b"<html" in data, path
