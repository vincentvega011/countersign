"""The agent's signing key. It lives in this process only (Decision 98).

The private half is never returned, printed or put in an exception: the only operations are `sign`,
the public `jwk` and `thumbprint`, and `save` to a private file the caller names (mode 0600, outside the
repository by the caller's choice). `repr`, `str`, copying and pickling reveal nothing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, NoReturn

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from agents.shopper import wire


class AgentKey:
    __slots__ = ("_private",)

    def __init__(self, private: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._private = private or ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def load(cls, path: Path) -> AgentKey:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise wire.WireError("not an EC key file")
        return cls(loaded)

    def save(self, path: Path) -> None:
        """Write the key to a new file readable by the owner only. Refuses to overwrite."""
        pem = self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)

    @property
    def jwk(self) -> dict[str, str]:
        numbers = self._private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": wire.b64url(numbers.x.to_bytes(32, "big")),
            "y": wire.b64url(numbers.y.to_bytes(32, "big")),
        }

    @property
    def thumbprint(self) -> str:
        return wire.thumbprint(self.jwk)

    def sign(self, data: bytes) -> str:
        """ES256 over `data`, as the raw `r || s` form in unpadded base64url."""
        r, s = decode_dss_signature(self._private.sign(data, ec.ECDSA(hashes.SHA256())))
        return wire.b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def __repr__(self) -> str:
        return f"AgentKey({self.thumbprint[:8]}...)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("an agent key cannot be pickled")

    def __copy__(self) -> NoReturn:
        raise TypeError("an agent key cannot be copied")

    def __deepcopy__(self, memo: Any) -> NoReturn:
        raise TypeError("an agent key cannot be copied")
