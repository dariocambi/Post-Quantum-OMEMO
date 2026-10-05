from __future__ import annotations

from typing import cast

import google.protobuf.message

from ..pqkem.keys import KemKeyPair, KemPrivateKey, KemPublicKey
from .storage_pb2 import PqSignedPreKeyRecordStructure  # pyright: ignore


class PqSignedPreKeyRecord:
    def __init__(self, structure: PqSignedPreKeyRecordStructureProto) -> None:
        self._structure = structure

    @classmethod
    def new(
        cls, _id: int, timestamp: int, kem_key_pair: KemKeyPair, signature: bytes
    ) -> PqSignedPreKeyRecord:
        record = cast(PqSignedPreKeyRecordStructureProto, PqSignedPreKeyRecordStructure())

        record.id = _id
        record.publicKey = kem_key_pair.get_public_key().serialize()
        record.privateKey = kem_key_pair.get_private_key().serialize()
        record.signature = signature
        record.timestamp = timestamp

        return cls(record)

    @classmethod
    def from_bytes(cls, serialized: bytes) -> PqSignedPreKeyRecord:
        record = cast(PqSignedPreKeyRecordStructureProto, PqSignedPreKeyRecordStructure())
        record.ParseFromString(serialized)
        return cls(record)

    def get_id(self) -> int:
        return self._structure.id

    def get_timestamp(self) -> int:
        return self._structure.timestamp

    def get_key_pair(self) -> KemKeyPair:
        public_key = KemPublicKey.from_bytes(self._structure.publicKey)
        private_key = KemPrivateKey.from_bytes(self._structure.privateKey)

        return KemKeyPair(public_key, private_key)

    def get_signature(self) -> bytes:
        return self._structure.signature

    def serialize(self) -> bytes:
        return self._structure.SerializeToString()


class PqSignedPreKeyRecordStructureProto(google.protobuf.message.Message):
    id: int
    publicKey: bytes
    privateKey: bytes
    signature: bytes
    timestamp: int
