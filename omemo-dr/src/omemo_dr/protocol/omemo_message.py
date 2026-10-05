from __future__ import annotations

from typing import cast

import hashlib
import hmac

import google.protobuf.message

from ..ecc.curve import Curve
from ..ecc.djbec import CurvePublicKey
from ..exceptions import InvalidKeyException
from ..exceptions import InvalidMessageException
from ..identitykey import IdentityKey
from ..util.byteutil import ByteUtil
from . import omemo_pb2
from .ciphertextmessage import CiphertextMessage

MAC_LENGTH = 16


class OMEMOMessage(CiphertextMessage):
    def __init__(
        self,
        serialized: bytes,
        sender_ratchet_key: CurvePublicKey,
        counter: int,
        previous_counter: int,
        ciphertext: bytes,
    ):
        self._serialized = serialized
        self._sender_ratchet_key = sender_ratchet_key
        self._counter = counter
        self._previous_counter = previous_counter
        self._ciphertext = ciphertext

    @classmethod
    def new(
        cls,
        message_version: int,
        mac_key: bytes,
        ec_public_key_sender_ratchet_key: CurvePublicKey,
        counter: int,
        previous_counter: int,
        ciphertext: bytes,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
    ) -> OMEMOMessage:
        omemo_message = cast(
            OMEMOMessageProto, omemo_pb2.OMEMOMessage()  # pyright: ignore
        )

        omemo_message.dh_pub = ec_public_key_sender_ratchet_key.serialize()
        omemo_message.n = counter
        omemo_message.pn = previous_counter
        omemo_message.ciphertext = ciphertext
        omemo_message = omemo_message.SerializeToString()

        mac = cls.get_mac(
            sender_identity_key, receiver_identity_key, mac_key, omemo_message
        )

        authenticated_message = cast(
            OMEMOAuthenticatedMessageProto,
            omemo_pb2.OMEMOAuthenticatedMessage(),  # pyright: ignore
        )
        authenticated_message.mac = mac
        authenticated_message.message = omemo_message
        authenticated_message = authenticated_message.SerializeToString()

        return cls(
            authenticated_message,
            ec_public_key_sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
        )

    @classmethod
    def from_bytes(cls, serialized: bytes) -> OMEMOMessage:
        authenticated_message = cast(
            OMEMOAuthenticatedMessageProto,
            omemo_pb2.OMEMOAuthenticatedMessage(),  # pyright: ignore
        )
        try:
            authenticated_message.ParseFromString(serialized)
        except google.protobuf.message.DecodeError as error:
            raise InvalidMessageException(str(error))

        omemo_message = cast(
            OMEMOMessageProto, omemo_pb2.OMEMOMessage()  # pyright: ignore
        )

        try:
            omemo_message.ParseFromString(authenticated_message.message)
        except google.protobuf.message.DecodeError as error:
            raise InvalidMessageException(str(error))

        try:
            sender_ratchet_key = Curve.decode_point(omemo_message.dh_pub)
            assert isinstance(sender_ratchet_key, CurvePublicKey)
        except InvalidKeyException as error:
            raise InvalidMessageException(str(error))

        return OMEMOMessage(
            serialized,
            sender_ratchet_key,
            omemo_message.n,
            omemo_message.pn,
            omemo_message.ciphertext,
        )

    def get_sender_ratchet_key(self) -> CurvePublicKey:
        return self._sender_ratchet_key

    def get_message_version(self) -> int:
        return 4

    def get_counter(self) -> int:
        return self._counter

    def get_body(self) -> bytes:
        return self._ciphertext

    def verify_mac(
        self,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
        mac_key: bytes,
    ):
        parts = ByteUtil.split(
            self._serialized,
            len(self._serialized) - MAC_LENGTH,
            MAC_LENGTH,
        )

        our_mac = self.get_mac(
            sender_identity_key, receiver_identity_key, mac_key, parts[0]
        )
        their_mac = parts[1]

        if our_mac != their_mac:
            raise InvalidMessageException("Bad Mac!")

    @classmethod
    def get_mac(
        cls,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
        mac_key: bytes,
        serialized: bytes,
    ) -> bytes:
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        mac.update(sender_identity_key.get_public_key().serialize())
        mac.update(receiver_identity_key.get_public_key().serialize())
        mac.update(bytes(serialized))
        full_mac = mac.digest()
        return ByteUtil.trim(full_mac, MAC_LENGTH)

    def serialize(self) -> bytes:
        return self._serialized

    def get_type(self) -> int:
        return CiphertextMessage.WHISPER_TYPE


class OMEMOMessageProto(google.protobuf.message.Message):
    n: int
    pn: int
    dh_pub: bytes
    ciphertext: bytes


class OMEMOAuthenticatedMessageProto(google.protobuf.message.Message):
    mac: bytes
    message: bytes
