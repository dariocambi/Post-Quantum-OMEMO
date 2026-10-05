from __future__ import annotations

from typing import cast

import google.protobuf.message
from google.protobuf.message import DecodeError

from ..ecc.curve import Curve
from ..ecc.ec import ECPublicKey
from ..exceptions import InvalidKeyException
from ..exceptions import InvalidMessageException
from ..identitykey import IdentityKey
from . import omemo_pb2
from .ciphertextmessage import CiphertextMessage
from .omemo_message import OMEMOMessage


class OMEMOKeyExchange(CiphertextMessage):
    def __init__(
        self,
        serialized: bytes,
        message_version: int,
        device_id: int,
        pre_key_id: int,
        signed_pre_key_id: int,
        ec_public_base_key: ECPublicKey,
        identity_key: IdentityKey,
        omemo_message: OMEMOMessage,
    ):
        self._message_version = message_version
        self._device_id = device_id
        self._pre_key_id = pre_key_id
        self._signed_pre_key_id = signed_pre_key_id
        self._base_key = ec_public_base_key
        self._identity_key = identity_key
        self._message = omemo_message
        self._serialized = serialized

    @classmethod
    def new(
        cls,
        message_version: int,
        device_id: int,
        pre_key_id: int,
        signed_pre_key_id: int,
        ec_public_base_key: ECPublicKey,
        identity_key: IdentityKey,
        omemo_message: OMEMOMessage,
    ) -> OMEMOKeyExchange:
        key_exchange = cast(
            OMEMOKeyExchangeProto, omemo_pb2.OMEMOKeyExchange()  # pyright: ignore
        )
        key_exchange.pk_id = pre_key_id
        key_exchange.spk_id = signed_pre_key_id
        key_exchange.ik = identity_key.serialize()
        key_exchange.ek = ec_public_base_key.serialize()
        key_exchange.message = omemo_message.serialize()

        serialized = key_exchange.SerializeToString()

        return cls(
            serialized,
            4,
            0,
            pre_key_id,
            signed_pre_key_id,
            ec_public_base_key,
            identity_key,
            omemo_message,
        )

    @classmethod
    def from_bytes(cls, serialized: bytes) -> OMEMOKeyExchange:
        try:
            key_exchange = cast(
                OMEMOKeyExchangeProto, omemo_pb2.OMEMOKeyExchange()  # pyright: ignore
            )
            key_exchange.ParseFromString(serialized)

            if (
                not key_exchange.spk_id
                or not key_exchange.ek
                or not key_exchange.ik
                or not key_exchange.message
            ):
                raise InvalidMessageException("Incomplete message")

            pre_key_id = key_exchange.pk_id
            signed_pre_key_id = key_exchange.spk_id
            ec_public_base_key = Curve.decode_point(key_exchange.ek)
            identity_key = IdentityKey(Curve.decode_point(key_exchange.ik))
            omemo_message = OMEMOMessage.from_bytes(key_exchange.message)

        except (InvalidKeyException, DecodeError) as error:
            raise InvalidMessageException(str(error))

        return cls(
            serialized,
            4,
            0,
            pre_key_id,
            signed_pre_key_id,
            ec_public_base_key,
            identity_key,
            omemo_message,
        )

    def get_message_version(self) -> int:
        return 4

    def get_identity_key(self) -> IdentityKey:
        return self._identity_key

    def get_device_id(self) -> int:
        return self._device_id

    def get_pre_key_id(self) -> int:
        return self._pre_key_id

    def get_signed_pre_key_id(self) -> int:
        return self._signed_pre_key_id

    def get_base_key(self) -> ECPublicKey:
        return self._base_key

    def get_whisper_message(self) -> OMEMOMessage:
        return self._message

    def serialize(self) -> bytes:
        return self._serialized

    def get_type(self) -> int:
        return CiphertextMessage.PREKEY_TYPE


class OMEMOKeyExchangeProto(google.protobuf.message.Message):
    pk_id: int
    spk_id: int
    ik: bytes
    ek: bytes
    message: bytes
