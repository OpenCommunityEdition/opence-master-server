#!/usr/bin/env python3
"""A reference publisher for the OpenCE master protocol, version 1.

It does what a dedicated server does with a master, without the game: it
makes and reads publisher keys, signs requests (OpenCE-Ed25519), builds a
host-signed listing exactly as the game's p2p_lobby.c (listing_make) does,
publishes it, answers the master's UDP probe, and checks a signed list.
The conformance test (test_master_protocol.py) drives a master with it;
anyone writing a master or a publisher may use it as a second opinion.

Python's standard library only. Ed25519 comes from the `cryptography`
package when it is installed, otherwise from the pure-Python code below
(RFC 8032's reference algorithm, slow but exact). The password listing's
sealed token uses XChaCha20-Poly1305, written here in pure Python.

Command line:
    opence_publisher.py keygen --out publisher.key
    opence_publisher.py sign --key publisher.key <text>
    opence_publisher.py publish --master http://127.0.0.1:8090 --key publisher.key \\
        --instance main --tunnel-port 2302 --name "My server" [--master-key ed25519:<hex>]
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

PROTOCOL = 1
LABEL = "OpenCE-Master-v1"
NETWORK_VERSION = 38

# ---------------------------------------------------------------- Ed25519

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - depends on the machine
    HAVE_CRYPTOGRAPHY = False
# (OPENCE_PUBLISHER_PURE=1 tests the pure-Python code where the package is installed)
if os.environ.get("OPENCE_PUBLISHER_PURE") == "1":
    HAVE_CRYPTOGRAPHY = False

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inverse(x):
    return pow(x, _P - 2, _P)


def _add(a, b):
    x = (a[1] - a[0]) * (b[1] - b[0]) % _P
    y = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    z = 2 * a[2] * b[2] % _P
    e, f, g, h = y - x, z - c, z + c, y + x
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inverse(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inverse(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(point):
    z = _inverse(point[2])
    x, y = point[0] * z % _P, point[1] * z % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand(seed):
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def _hash_scalar(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def pure_public_key(seed):
    a, _ = _expand(seed)
    return _compress(_multiply(a, _G))


def pure_sign(seed, message):
    a, prefix = _expand(seed)
    public = _compress(_multiply(a, _G))
    r = _hash_scalar(prefix + message)
    big_r = _compress(_multiply(r, _G))
    s = (r + _hash_scalar(big_r + public + message) * a) % _Q
    return big_r + s.to_bytes(32, "little")


def pure_verify(public, message, signature):
    if len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = _hash_scalar(signature[:32] + public + message)
    return _equal(_multiply(s, _G), _add(r, _multiply(h, a)))


def public_key(seed):
    """The Ed25519 public key (32 bytes) of a 32-byte seed."""
    if HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pure_public_key(seed)


def sign(seed, message):
    """An RFC 8032 Ed25519 signature (64 bytes)."""
    if HAVE_CRYPTOGRAPHY:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return pure_sign(seed, message)


def verify(public, message, signature):
    if HAVE_CRYPTOGRAPHY:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    return pure_verify(public, message, signature)


# ---------------------------------------------------------------- keys and ids

def new_seed():
    return os.urandom(32)


def read_key_file(path):
    """A key file: 64 hexadecimal digits on the first line that is not empty; '#' starts a comment."""
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                seed = bytes.fromhex(line)
                if len(seed) != 32:
                    raise ValueError("a key file holds 64 hexadecimal digits")
                return seed
    raise ValueError("the key file is empty")


def write_key_file(path, seed):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as f:
        f.write(seed.hex() + "\n")


def public_key_text(public):
    return "ed25519:" + public.hex()


def parse_public_key(text):
    text = text.strip().lower()
    if text.startswith("ed25519:"):
        text = text[8:]
    key = bytes.fromhex(text)
    if len(key) != 32:
        raise ValueError("a public key is 32 bytes")
    return key


def key_id_bytes(public):
    """The first 8 bytes of SHA-256 of the public key."""
    return hashlib.sha256(public).digest()[:8]


def key_id(public):
    """key_id_bytes in lowercase hexadecimal (16 characters)."""
    return key_id_bytes(public).hex()


def server_id(key_id_text, instance):
    """The first 16 hexadecimal digits of SHA-256(key id's 16 characters, then the instance's)."""
    return hashlib.sha256((key_id_text + instance).encode("ascii")).hexdigest()[:16]


# ---------------------------------------------------------------- request signatures

def body_hash(body):
    return hashlib.sha256(body).hexdigest()


def canonical(master_key_id, method, path, ts, nonce, body):
    """The signed string: the label, the receiving master's key id (16 lowercase hexadecimal digits, of
    the key pinned for it in masters.txt), the method, the path, ts, the nonce and the body's hash, joined
    by line feeds."""
    return "\n".join([LABEL, master_key_id, method, path, str(ts), nonce, body_hash(body)])


def authorization(seed, master_key_id, method, path, body=b"", ts=None, nonce=None):
    """The Authorization header's value for a request to the master whose key id is master_key_id."""
    if not isinstance(master_key_id, str) or len(master_key_id) != 16:
        raise ValueError("master_key_id is the master's key id: 16 hexadecimal digits")
    ts = int(time.time()) if ts is None else ts
    nonce = os.urandom(16).hex() if nonce is None else nonce
    signature = sign(seed, canonical(master_key_id.lower(), method, path, ts, nonce, body).encode("ascii"))
    return "OpenCE-Ed25519 keyid=%s, ts=%d, nonce=%s, sig=%s" % (
        key_id(public_key(seed)), ts, nonce, base64.b64encode(signature).decode("ascii"))


def verify_list(body, headers, master_public, maximum_age=300, now=None):
    """Checks a signed body (a list, a server, the shared approvals): the Signature header is
    the master's over the exact bytes, Signature-Key its key id, and the body's master.time
    (which the signature covers) is fresh. Returns the parsed body; raises ValueError."""
    value = headers.get("Signature", "")
    if not value.startswith("ed25519="):
        raise ValueError("no Signature header")
    if headers.get("Signature-Key") != key_id(master_public):
        raise ValueError("Signature-Key is not the master's key id")
    if not verify(master_public, body, base64.b64decode(value[8:])):
        raise ValueError("the signature does not verify")
    parsed = json.loads(body)
    now = time.time() if now is None else now
    if parsed.get("protocol") != PROTOCOL or parsed["master"]["key_id"] != key_id(master_public):
        raise ValueError("not this master's protocol 1 body")
    if abs(now - parsed["master"]["time"]) > maximum_age:
        raise ValueError("the body is stale")
    if str(parsed["master"]["time"]) != headers.get("Signature-Time"):
        raise ValueError("Signature-Time is not the body's time")
    return parsed


# ---------------------------------------------------------------- XChaCha20-Poly1305 (Monocypher's crypto_aead_lock)

def _rotate(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotate(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotate(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotate(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotate(s[b] ^ s[c], 7)


def _rounds(state):
    s = list(state)
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return s


_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def hchacha20(key, nonce16):
    s = _rounds(list(_SIGMA) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16)))
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def chacha20_block(key, counter, nonce12):
    state = list(_SIGMA) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce12))
    mixed = _rounds(state)
    return struct.pack("<16I", *[(mixed[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(key, counter, nonce12, data):
    out = bytearray()
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce12)
        out += bytes(x ^ y for x, y in zip(data[offset:offset + 64], block))
    return bytes(out)


def poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16] + b"\x01"
        accumulator = (accumulator + int.from_bytes(chunk, "little")) * r % p
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data):
    return b"\x00" * (-len(data) % 16)


def xchacha20poly1305_lock(key, nonce24, plain, ad):
    """(mac, cipher text) as Monocypher's crypto_aead_lock makes them."""
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:]
    mac_key = chacha20_block(subkey, 0, nonce12)[:32]
    cipher = chacha20_xor(subkey, 1, nonce12, plain)
    mac = poly1305(mac_key, ad + _pad16(ad) + cipher + _pad16(cipher) + struct.pack("<QQ", len(ad), len(cipher)))
    return mac, cipher


def seal_token(password_key, signing_key, token, nonce=None):
    """The 56-byte sealed token of a password game's listing (p2p_seal_token): nonce (24), MAC (16),
    the token encrypted (16), the host's signing key as the additional data."""
    nonce = os.urandom(24) if nonce is None else nonce
    mac, cipher = xchacha20poly1305_lock(password_key, nonce, token, signing_key)
    return nonce + mac + cipher


def password_key(password, signing_key):
    """The password's key (p2p_password_key): Argon2id, 4 MiB, 3 passes, 1 lane, salted with the host's
    signing key. Needs the cryptography package's Argon2id."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    return Argon2id(salt=signing_key, length=32, iterations=3, lanes=1, memory_cost=4096).derive(password.encode())


# ---------------------------------------------------------------- the listing (p2p_lobby.c)

LISTING_OPEN, LISTING_IN_PROGRESS, LISTING_TEAMS, LISTING_CLOSED, LISTING_PASSWORD, LISTING_DEDICATED = 1, 2, 4, 8, 16, 32
SIGNATURE_LABEL = b"hceu-lobby-1"


def _text(value, maximum):
    data = value.encode("ascii", "replace")[:maximum]
    return bytes([len(data)]) + data


def make_listing(host_seed, name, map_name, gametype, players=0, max_players=16, engine=1, kind=0,
                 flags=LISTING_OPEN, sequence=1, unix_time=None, token=None, sealed=None,
                 network_version=NETWORK_VERSION):
    """A listing as listing_make writes it, signed with the host's key: "HL", format 1, network
    version (2), flags, sequence (4), time (4), the host key (32), the token (16) or with
    LISTING_PASSWORD the sealed token (56), players, most players, engine, name, map and gametype
    (a length byte and up to 32, 32, 24 bytes), the stamp (8: kind, then zeros), and the
    signature (64) of "hceu-lobby-1" and all before it."""
    unix_time = int(time.time()) if unix_time is None else unix_time
    host_public = public_key(host_seed)
    out = b"HL" + bytes([1]) + struct.pack(">HB", network_version, flags & 0xFF)
    out += struct.pack(">II", sequence, unix_time) + host_public
    if flags & LISTING_PASSWORD:
        if sealed is None:
            raise ValueError("a password listing carries its sealed token")
        out += sealed
    elif flags & LISTING_CLOSED:
        out += b"\x00" * 16
    else:
        out += token if token is not None else os.urandom(16)
    out += bytes([min(players, 255), min(max_players, 255), engine & 0xFF])
    out += _text(name, 32) + _text(map_name, 32) + _text(gametype, 24)
    out += bytes([kind & 0xFF]) + b"\x00" * 7
    return out + sign(host_seed, SIGNATURE_LABEL + out)


def read_listing(data):
    """Reads a listing as listing_read does and checks its signature; raises ValueError."""
    if not 140 <= len(data) <= 264 or data[:3] != b"HL\x01":
        raise ValueError("malformed")
    version, flags = struct.unpack(">HB", data[3:6])
    sequence, unix_time = struct.unpack(">II", data[6:14])
    key = data[14:46]
    offset = 46
    listing = {"network_version": version, "flags": flags, "sequence": sequence, "time": unix_time, "key": key}
    if flags & LISTING_PASSWORD:
        listing["sealed"] = data[offset:offset + 56]
        offset += 56
    else:
        listing["token"] = data[offset:offset + 16]
        offset += 16
    if offset + 3 > len(data):
        raise ValueError("malformed")
    listing["players"], listing["max_players"], listing["engine"] = data[offset], data[offset + 1], data[offset + 2]
    offset += 3
    for field, maximum in (("name", 32), ("map", 32), ("gametype", 24)):
        if offset >= len(data):
            raise ValueError("malformed")
        length = data[offset]
        offset += 1
        if length > maximum or offset + length > len(data):
            raise ValueError("malformed")
        raw = data[offset:offset + length].split(b"\x00", 1)[0]
        listing[field] = "".join(chr(c) if 0x20 <= c < 0x7F else "?" for c in raw)
        offset += length
    if offset + 8 + 64 != len(data):
        raise ValueError("malformed")
    listing["kind"] = data[offset]
    offset += 8
    if not verify(key, SIGNATURE_LABEL + data[:offset], data[offset:]):
        raise ValueError("bad signature")
    return listing


# ---------------------------------------------------------------- the probe

PROBE_MAGIC = b"OPCE-PROBE"
ACK_MAGIC = b"OPCE-PROBE-ACK"


def probe_packet(master_key_id, nonce):
    return PROBE_MAGIC + b"\x01" + master_key_id + nonce


def parse_probe(packet):
    """(master key id, nonce) of a 35-byte probe, or None."""
    if len(packet) != 35 or not packet.startswith(PROBE_MAGIC) or packet[10] != 1:
        return None
    return packet[11:19], packet[19:35]


def probe_answer(seed, master_key_id, nonce):
    """The 103-byte answer: magic, 1, the master key id, the nonce, and the publisher key's signature of
    "probe" || master key id || nonce."""
    return ACK_MAGIC + b"\x01" + master_key_id + nonce + sign(seed, b"probe" + master_key_id + nonce)


class ProbeResponder:
    """Answers probes on a UDP socket (the game's tunnel socket's part, server_master_probe): only for the
    master key ids given (those of its masters.txt), only to the address the probe came from, a given nonce
    at most once a second (by the wall clock's whole seconds), ten answers a second at most."""

    def __init__(self, seed, master_key_ids, host="127.0.0.1", port=0):
        self.seed = seed
        self.master_key_ids = set(master_key_ids)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.answered = 0
        self.ignored = 0
        self.event = threading.Event()
        self._seen = {}
        self._sent = []
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                packet, source = self.socket.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            probe = parse_probe(packet)
            second = int(time.time())
            self._sent = [t for t in self._sent if t == second]
            self._seen = {n: t for n, t in self._seen.items() if t == second}
            if probe is None or probe[0] not in self.master_key_ids or probe[1] in self._seen or len(self._sent) >= 10:
                self.ignored += 1
                continue
            self._seen[probe[1]] = second
            self._sent.append(second)
            self.socket.sendto(probe_answer(self.seed, probe[0], probe[1]), source)
            self.answered += 1
            self.event.set()

    def close(self):
        self._stop = True
        self._thread.join(2)
        self.socket.close()


# ---------------------------------------------------------------- HTTP

def request(base_url, method, path, body=None, seed=None, headers=None, raw_authorization=None, timeout=10,
            master_key_id=None):
    """A request to a master: (status, headers, body bytes). Signed with seed when given, for the master
    whose key id is master_key_id."""
    data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    all_headers = {"Content-Type": "application/json"} if body is not None else {}
    all_headers.update(headers or {})
    signed_path = path.split("?", 1)[0]
    if raw_authorization is not None:
        all_headers["Authorization"] = raw_authorization
    elif seed is not None:
        all_headers["Authorization"] = authorization(seed, master_key_id, method, signed_path, data)
    req = urllib.request.Request(base_url.rstrip("/") + path, data=data if body is not None else None,
                                 method=method, headers=all_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


class Publisher:
    """One server instance publishing to one master, whose key id (of its key in masters.txt) is
    master_key_id."""

    def __init__(self, base_url, master_key_id, seed, instance, tunnel_port, region="", build="reference",
                 variant=""):
        self.base_url = base_url
        self.master_key_id = master_key_id
        self.seed = seed
        self.instance = instance
        self.tunnel_port = tunnel_port
        self.region = region
        self.build = build
        self.variant = variant
        self.public = public_key(seed)
        self.key_id = key_id(self.public)
        self.server_id = server_id(self.key_id, instance)
        self.serial = 0

    def body(self, listing, closed=False, **extra):
        self.serial += 1
        body = {"protocol": PROTOCOL, "instance": self.instance, "dedicated": True, "build": self.build,
                "region": self.region, "variant": self.variant, "tunnel_port": self.tunnel_port,
                "closed": closed, "serial": self.serial}
        if listing is not None:
            body["listing"] = base64.b64encode(listing).decode("ascii")
        body.update(extra)
        return body

    def publish(self, listing, closed=False, **extra):
        status, headers, data = request(self.base_url, "PUT", "/v1/servers/" + self.server_id,
                                        self.body(listing, closed, **extra), self.seed,
                                        master_key_id=self.master_key_id)
        return status, json.loads(data or b"{}"), headers

    def delete(self):
        status, _, data = request(self.base_url, "DELETE", "/v1/servers/" + self.server_id, None, self.seed,
                                  master_key_id=self.master_key_id)
        return status, json.loads(data or b"{}")

    def me(self):
        status, _, data = request(self.base_url, "GET", "/v1/me", None, self.seed,
                                  master_key_id=self.master_key_id)
        return status, json.loads(data or b"{}")

    def add_key(self, public):
        status, _, data = request(self.base_url, "POST", "/v1/keys", {"public_key": public_key_text(public)},
                                  self.seed, master_key_id=self.master_key_id)
        return status, json.loads(data or b"{}")


def proof_of_key(seed, nonce):
    """An application's proof of key: the key's signature of the master's nonce, in hex, as
    `halo --server --sign <nonce>` prints it. (Applications are made with a master's Discord bot,
    whose /apply gives the nonce, or by its operator's `opence-master challenge` and
    `add-application`.)"""
    return sign(seed, nonce.encode("ascii")).hex()


# ---------------------------------------------------------------- command line

def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenCE master protocol: a reference publisher")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="write a new publisher key")
    keygen.add_argument("--out", required=True)
    signer = commands.add_parser("sign", help="sign a text (an application's proof of key: the nonce of a "
                                 "master's Discord bot's /apply), in hex")
    signer.add_argument("--key", required=True)
    signer.add_argument("text")
    publish = commands.add_parser("publish", help="publish a fake server every 30 s and answer probes")
    publish.add_argument("--master", required=True, help="the master's URL")
    publish.add_argument("--master-key", help="the master's public key (ed25519:<hex>), as masters.txt pins it; "
                         "without it, the one /v1/master says (for tests only)")
    publish.add_argument("--key", required=True, help="the publisher key file")
    publish.add_argument("--instance", default="main")
    publish.add_argument("--tunnel-port", type=int, default=2302)
    publish.add_argument("--name", default="Reference server")
    publish.add_argument("--map", default="bloodgulch")
    publish.add_argument("--gametype", default="CTF")
    publish.add_argument("--region", default="")
    args = parser.parse_args(argv)
    if args.command == "keygen":
        seed = new_seed()
        write_key_file(args.out, seed)
        public = public_key(seed)
        print("wrote %s\npublic key %s\nkey id     %s" % (args.out, public_key_text(public), key_id(public)))
        return 0
    if args.command == "sign":
        print(sign(read_key_file(args.key), args.text.encode()).hex())
        return 0
    seed = read_key_file(args.key)
    status, _, data = request(args.master, "GET", "/v1/master")
    master_public = parse_public_key(args.master_key or json.loads(data)["master"]["public_key"])
    responder = ProbeResponder(seed, [key_id_bytes(master_public)], host="0.0.0.0", port=args.tunnel_port)
    publisher = Publisher(args.master, key_id(master_public), seed, args.instance, responder.port,
                          region=args.region)
    host_seed = new_seed()
    token = os.urandom(16)
    sequence = 0
    try:
        while True:
            sequence += 1
            listing = make_listing(host_seed, args.name, args.map, args.gametype, sequence=sequence, token=token)
            status, answer, _ = publisher.publish(listing)
            print(status, json.dumps(answer), flush=True)
            time.sleep(30 if status == 200 else 5)
    except KeyboardInterrupt:
        publisher.publish(make_listing(host_seed, args.name, args.map, args.gametype, sequence=sequence + 1,
                                       flags=LISTING_CLOSED), closed=True)
        responder.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
