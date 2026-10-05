from __future__ import annotations

from typing import cast

import google.protobuf.message

from ..ecc.curve import Curve
from ..ecc.eckeypair import ECKeyPair
from . import storage_pb2


class PreKeyRecord:
    def __init__(self, structure: PreKeyRecordStructureProto) -> None:
        self._structure = structure

    @classmethod
    def new(
        cls,
        _id: int,
        ec_key_pair: ECKeyPair,
    ) -> PreKeyRecord:
        structure = cast(
            PreKeyRecordStructureProto,
            storage_pb2.PreKeyRecordStructure(),  # pyright: ignore
        )
        structure.id = _id
        structure.publicKey = ec_key_pair.get_public_key().serialize()
        structure.privateKey = ec_key_pair.get_private_key().serialize()
        return cls(structure)

    @classmethod
    def from_bytes(cls, serialized: bytes) -> PreKeyRecord:
        record = cast(
            PreKeyRecordStructureProto,
            storage_pb2.PreKeyRecordStructure(),  # pyright: ignore
        )
        record.ParseFromString(serialized)
        return cls(record)

    def get_id(self) -> int:
        return self._structure.id

    def get_key_pair(self):
        public_key = Curve.decode_point(self._structure.publicKey)
        private_key = Curve.decode_private_point(self._structure.privateKey)
        return ECKeyPair(public_key, private_key)

    def serialize(self) -> bytes:
        return self._structure.SerializeToString()


class PreKeyRecordStructureProto(google.protobuf.message.Message):
    id: int
    publicKey: bytes
    privateKey: bytes
