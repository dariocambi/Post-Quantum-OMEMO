from __future__ import annotations

from ..exceptions import InvalidKeyException
from ..const import PQ_KEM_PRIVATE_KEY_LENGTH, PQ_KEM_PUBLIC_KEY_LENGTH


class KemPublicKey:

    def __init__(self, _bytes: bytes) -> None:
        self._public_key = _bytes

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KemPublicKey): return False
        return self._public_key == other.serialize()


    @classmethod
    def from_bytes(cls, data: bytes) -> KemPublicKey:

        if not isinstance(data, bytes) or len(data) != PQ_KEM_PUBLIC_KEY_LENGTH:
            raise InvalidKeyException(f'Unknown KEM key type or length: {len(data)}')

        return cls(data)


    def serialize(self) -> bytes:
        return self._public_key


class KemPrivateKey:

    def __init__(self, _bytes: bytes) -> None:
        self._private_key = _bytes

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KemPrivateKey): return False
        return self._private_key == other.serialize()


    @classmethod
    def from_bytes(cls, data: bytes) -> KemPrivateKey:

        if not isinstance(data, bytes) or len(data) != PQ_KEM_PRIVATE_KEY_LENGTH:
            raise InvalidKeyException(f'Unknown KEM key type or length: {len(data)}')

        return cls(data)


    def serialize(self) -> bytes:
        return self._private_key


class KemKeyPair:

    def __init__(self, public_key: KemPublicKey, private_key: KemPrivateKey) -> None:
        self._public_key = public_key
        self._private_key = private_key

    def get_public_key(self) -> KemPublicKey:
        return self._public_key

    def get_private_key(self) -> KemPrivateKey:
        return self._private_key
