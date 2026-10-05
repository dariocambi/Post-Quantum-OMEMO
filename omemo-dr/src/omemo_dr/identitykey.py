from __future__ import annotations

from typing import Union

import binascii
import textwrap

from .ecc.curve import Curve
from .ecc.djbec import CurvePublicKey


class IdentityKey:
    def __init__(
        self,
        ec_pub_key_or_bytes: Union[CurvePublicKey, bytes],
    ) -> None:
        if isinstance(ec_pub_key_or_bytes, CurvePublicKey):
            self._public_key = ec_pub_key_or_bytes
        else:
            self._public_key = Curve.decode_point(ec_pub_key_or_bytes)

    def get_public_key(self) -> CurvePublicKey:
        return self._public_key

    def serialize(self) -> bytes:
        return self._public_key.serialize()

    def get_fingerprint(self, formatted: bool = False) -> str:
        public_key = self.serialize()
        fingerprint = binascii.hexlify(public_key).decode()[2:]
        if not formatted:
            return fingerprint
        fplen = len(fingerprint)
        wordsize = fplen // 8
        buf = ""
        for word in range(0, fplen, wordsize):
            buf += f"{fingerprint[word : word + wordsize]} "
        buf = textwrap.fill(buf, width=36)
        return buf.rstrip().upper()

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, IdentityKey)
        return self._public_key == other.get_public_key()

    def __hash__(self) -> int:
        return hash(self._public_key.serialize())
