from __future__ import annotations

from typing import cast

import google.protobuf.message

from ..ecc.curve import Curve
from ..ecc.eckeypair import ECKeyPair
from .storage_pb2 import SignedPreKeyRecordStructure  # pyright: ignore


class SignedPreKeyRecord:
    def __init__(self, structure: SignedPreKeyRecordStructureProto) -> None:
        self._structure = structure

    @classmethod
    def new(
        cls, _id: int, timestamp: int, ec_key_pair: ECKeyPair, signature: bytes
    ) -> SignedPreKeyRecord:
        record = cast(SignedPreKeyRecordStructureProto, SignedPreKeyRecordStructure())

        record.id = _id
        record.publicKey = ec_key_pair.get_public_key().serialize()
        record.privateKey = ec_key_pair.get_private_key().serialize()
        record.signature = signature
        record.timestamp = timestamp

        return cls(record)

    @classmethod
    def from_bytes(cls, serialized: bytes) -> SignedPreKeyRecord:
        record = cast(SignedPreKeyRecordStructureProto, SignedPreKeyRecordStructure())
        record.ParseFromString(serialized)
        return cls(record)

    def get_id(self) -> int:
        return self._structure.id

    def get_timestamp(self) -> int:
        return self._structure.timestamp

    def get_key_pair(self) -> ECKeyPair:
        public_key = Curve.decode_point(self._structure.publicKey)
        private_key = Curve.decode_private_point(self._structure.privateKey)

        return ECKeyPair(public_key, private_key)

    def get_signature(self) -> bytes:
        return self._structure.signature

    def serialize(self) -> bytes:
        return self._structure.SerializeToString()


class SignedPreKeyRecordStructureProto(google.protobuf.message.Message):
    id: int
    publicKey: bytes
    privateKey: bytes
    signature: bytes
    timestamp: int
