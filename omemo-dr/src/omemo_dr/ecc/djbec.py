from __future__ import annotations

from typing import Any

import binascii

from .. import curve
from ..const import ENCODED_KEY_LENGTH
from ..const import LEGACY_ENCODED_KEY_LENGTH
from ..exceptions import InvalidKeyException
from ..util.byteutil import ByteUtil
from .ec import ECPrivateKey
from .ec import ECPublicKey

DJB_TYPE = 0x05


class DjbECPublicKey(ECPublicKey):
    def __init__(self, _bytes: bytes) -> None:
        self._public_key = _bytes

    def get_bytes(self) -> bytes:
        return self._public_key

    def get_public_key(self) -> bytes:
        return self._public_key

    def __eq__(self, other: Any) -> bool:
        return self._public_key == other.get_public_key()

    def __lt__(self, other: Any) -> bool:
        my_val = int(binascii.hexlify(self._public_key), 16)
        other_val = int(binascii.hexlify(other.get_public_key()), 16)

        return my_val < other_val

    def __cmp__(self, other: Any) -> int:
        my_val = int(binascii.hexlify(self._public_key), 16)
        other_val = int(binascii.hexlify(other.get_public_key()), 16)

        if my_val < other_val:
            return -1
        elif my_val == other_val:
            return 0
        else:
            return 1


class CurvePublicKey(DjbECPublicKey):
    @classmethod
    def from_bytes(cls, bytes_: bytes) -> CurvePublicKey:
        key_length = len(bytes_)
        if key_length == LEGACY_ENCODED_KEY_LENGTH and bytes_[0] == 0x05:
            return cls(bytes_[1:])

        if key_length == ENCODED_KEY_LENGTH:
            return cls(bytes_)

        raise InvalidKeyException("Unknown key type or length: %s" % bytes_)

    def serialize(self) -> bytes:
        return ByteUtil.combine([DJB_TYPE], self._public_key)

    def to_ed(self) -> EdPublicKey:
        return EdPublicKey(curve.convert_curve_to_ed_pubkey(self._public_key))


class EdPublicKey(DjbECPublicKey):
    @classmethod
    def from_bytes(cls, bytes_: bytes) -> EdPublicKey:
        key_length = len(bytes_)
        if key_length == ENCODED_KEY_LENGTH:
            return cls(bytes_)

        raise InvalidKeyException("Unknown key type or length: %s" % bytes_)

    def to_curve(self) -> CurvePublicKey:
        return CurvePublicKey(curve.convert_ed_to_curve_pubkey(self._public_key))

    def serialize(self) -> bytes:
        return self._public_key


class DjbECPrivateKey(ECPrivateKey):
    def __init__(self, private_key: bytes) -> None:
        self._private_key = private_key

    def get_private_key(self) -> bytes:
        return self._private_key

    def serialize(self) -> bytes:
        return self._private_key

    def __eq__(self, other: Any) -> bool:
        return self._private_key == other.get_private_key()
