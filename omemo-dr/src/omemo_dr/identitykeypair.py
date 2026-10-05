from __future__ import annotations

from typing import cast

import google.protobuf.message

from .ecc.curve import Curve
from .ecc.djbec import DjbECPrivateKey
from .identitykey import IdentityKey
from .state import storage_pb2


class IdentityKeyPair:
    def __init__(self, structure: IdentityKeyPairStructureProto) -> None:
        self._structure = structure

    @classmethod
    def new(
        cls,
        identity_key_public_key: IdentityKey,
        ec_private_key: DjbECPrivateKey,
    ) -> IdentityKeyPair:
        structure = cast(
            IdentityKeyPairStructureProto,
            storage_pb2.IdentityKeyPairStructure(),  # pyright: ignore
        )

        structure.publicKey = identity_key_public_key.serialize()
        structure.privateKey = ec_private_key.serialize()

        return cls(structure)

    @classmethod
    def from_bytes(cls, serialized: bytes) -> IdentityKeyPair:
        structure = cast(
            IdentityKeyPairStructureProto,
            storage_pb2.IdentityKeyPairStructure(),  # pyright: ignore
        )
        structure.ParseFromString(serialized)
        return cls(structure)

    def get_public_key(self) -> IdentityKey:
        return IdentityKey(self._structure.publicKey)

    def get_private_key(self) -> DjbECPrivateKey:
        return Curve.decode_private_point(self._structure.privateKey)

    def serialize(self) -> bytes:
        return self._structure.SerializeToString()


class IdentityKeyPairStructureProto(google.protobuf.message.Message):
    publicKey: bytes
    privateKey: bytes
