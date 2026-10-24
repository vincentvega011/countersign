"""Merchant signing key: load, validate, generate.

The merchant key signs every Checkout JWT and `ap2.merchant_authorization`. A wrong key type is a
silent security failure, because the verifier on the other side picks the algorithm from the
header, so the rules here are strict and the service refuses to start on any violation.

Rules for a key file, all checked on load:

- The file is a regular file (not a symlink) readable by the owner only. A group or world
  readable private key is refused rather than warned about.
- The JSON has no duplicate keys, and holds exactly one JWK object with only the members
  `kty crv x y d alg use kid`. Unknown members are refused, so nothing unexpected is ever copied
  into a public profile.
- `kty` is `EC`, `crv` is `P-256`, `alg` is `ES256` and is required to be present (a key without
  an `alg` could be reused with another algorithm). `use`, when present, is `sig`.
- The public point is on the curve and matches the private scalar `d`, so a file whose `x` and
  `y` were edited cannot advertise a different key than the one that signs.
- `kid` equals the RFC 7638 thumbprint of the public key (docs/PROTOCOL.md, Decision 16), so the
  identifier cannot be chosen to collide with another key.

Nothing in this module logs or formats key material. Error messages name the rule, never a value.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from countersign.canonical.hashing import b64url
from countersign.canonical.jsonstrict import StrictJsonError, loads_strict

ALG = "ES256"
CURVE = "P-256"
KTY = "EC"

# Members a private key file may hold, and the subset that may leave the process.
_PRIVATE_MEMBERS = frozenset({"kty", "crv", "x", "y", "d", "alg", "use", "kid"})
PUBLIC_MEMBERS = ("kty", "crv", "x", "y", "alg", "use", "kid")
PRIVATE_ONLY_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

# Raw coordinate and scalar length of P-256, in base64url characters (32 bytes, unpadded).
_COORD_LEN = 43


class MerchantKeyError(Exception):
    """The merchant key is missing or violates a rule. The service must not start."""

    code = "merchant_key_invalid"


@dataclass(frozen=True)
class MerchantKey:
    """A validated ES256 merchant key. `repr` shows the public JWK only."""

    kid: str
    public_jwk: dict[str, str]
    _private: ECKey = field(repr=False)

    @property
    def private_key(self) -> ECKey:
        return self._private


def thumbprint(x: str, y: str) -> str:
    """RFC 7638 thumbprint of a P-256 key, computed independently of joserfc.

    The hash input is the JSON of the required members `crv kty x y` in lexicographic order with
    no whitespace (RFC 7638 section 3.2). Values are base64url strings with no characters that
    need escaping, so the text is built directly.
    """
    text = f'{{"crv":"{CURVE}","kty":"{KTY}","x":"{x}","y":"{y}"}}'
    return b64url(hashlib.sha256(text.encode("ascii")).digest())


def _reject(rule: str) -> MerchantKeyError:
    return MerchantKeyError(rule)


def _check_file(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise _reject("key file is missing; run `make keys`") from None
    except OSError:
        raise _reject("key file cannot be read") from None
    # lstat does not follow links, so a symlink is not S_ISREG and is refused here too.
    if not stat.S_ISREG(st.st_mode):
        raise _reject("key file must be a regular file, not a link")
    if st.st_mode & 0o077:
        raise _reject("key file must be readable by its owner only (mode 600)")


def _check_b64(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != _COORD_LEN:
        raise _reject(f"member {name} must be a 32 byte base64url string")
    if not all(c.isascii() and (c.isalnum() or c in "-_") for c in value):
        raise _reject(f"member {name} is not base64url")
    return value


def validate_jwk(jwk: Any) -> MerchantKey:
    """Validate a parsed private JWK against every rule in the module docstring."""
    if not isinstance(jwk, dict):
        raise _reject("key file must hold one JSON object")
    extra = set(jwk) - _PRIVATE_MEMBERS
    if extra:
        raise _reject("key file has members outside the allowed set")
    if jwk.get("kty") != KTY:
        raise _reject("kty must be EC")
    if jwk.get("crv") != CURVE:
        raise _reject("crv must be P-256")
    if jwk.get("alg") != ALG:
        raise _reject("alg must be present and ES256")
    if "use" in jwk and jwk["use"] != "sig":
        raise _reject("use must be sig when present")
    x = _check_b64(jwk.get("x"), "x")
    y = _check_b64(jwk.get("y"), "y")
    d = _check_b64(jwk.get("d"), "d")
    kid = jwk.get("kid")
    if kid != thumbprint(x, y):
        raise _reject("kid must equal the RFC 7638 thumbprint of the public key")

    # Derive the public point from d and compare it with the advertised x and y. Deriving from
    # the scalar (not importing the pair) is what makes an edited x or y detectable here.
    try:
        derived = ec.derive_private_key(int.from_bytes(_decode(d), "big"), ec.SECP256R1())
    except ValueError:
        raise _reject("private scalar is not valid for P-256") from None
    point = derived.public_key().public_numbers()
    if point.x.to_bytes(32, "big") != _decode(x) or point.y.to_bytes(32, "big") != _decode(y):
        raise _reject("public members do not match the private scalar")
    try:
        key = ECKey.import_key({m: jwk[m] for m in ("kty", "crv", "x", "y", "d")})
    except (ValueError, JoseError):
        raise _reject("key does not parse as a P-256 private key") from None

    public: dict[str, str] = {m: jwk[m] for m in PUBLIC_MEMBERS if m in jwk}
    return MerchantKey(kid=kid, public_jwk=public, _private=key)


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=")


def load_merchant_key(path: str | os.PathLike[str]) -> MerchantKey:
    """Load and validate the key file. Raises `MerchantKeyError`; never returns a weak key."""
    p = Path(path)
    _check_file(p)
    try:
        raw = p.read_bytes()
        parsed = loads_strict(raw)
    except (OSError, StrictJsonError):
        raise _reject("key file is not valid strict JSON") from None
    return validate_jwk(parsed)


def generate_jwk() -> dict[str, str]:
    """A fresh ES256 private JWK with a thumbprint `kid`."""
    key = ECKey.generate_key(CURVE)
    raw = key.as_dict(private=True)
    jwk: dict[str, str] = {m: str(raw[m]) for m in ("kty", "crv", "x", "y", "d")}
    jwk["alg"] = ALG
    jwk["use"] = "sig"
    jwk["kid"] = thumbprint(jwk["x"], jwk["y"])
    return jwk


def write_key_file(path: str | os.PathLike[str]) -> str:
    """Create a new key file with mode 600 and return its `kid`.

    Refuses to overwrite: replacing the signing key would invalidate every outstanding mandate
    and receipt, so rotation must be a deliberate act (delete the file first).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    jwk = generate_jwk()
    data = (json.dumps(jwk, indent=2) + "\n").encode("ascii")
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise _reject("key file already exists; refusing to overwrite") from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return jwk["kid"]
