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
from . import whisper_pb2
from .ciphertextmessage import CiphertextMessage

MAC_LENGTH = 8


class WhisperMessage(CiphertextMessage):
    def __init__(
        self,
        serialized: bytes,
        sender_ratchet_key: CurvePublicKey,
        counter: int,
        previous_counter: int,
        ciphertext: bytes,
    ) -> None:
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
    ) -> WhisperMessage:
        version = ByteUtil.ints_to_byte_high_and_low(message_version, message_version)

        message = cast(
            WhisperMessageProto, whisper_pb2.WhisperMessage()  # pyright: ignore
        )
        message.ratchetKey = ec_public_key_sender_ratchet_key.serialize()
        message.counter = counter
        message.previousCounter = previous_counter
        message.ciphertext = ciphertext
        message = message.SerializeToString()

        mac = cls.get_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            ByteUtil.combine(version, message),
        )

        serialized = ByteUtil.combine(version, message, mac)

        return cls(
            serialized,
            ec_public_key_sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
        )

    @classmethod
    def from_bytes(cls, serialized: bytes) -> WhisperMessage:
        message_parts = ByteUtil.split(
            serialized,
            1,
            len(serialized) - 1 - MAC_LENGTH,
            MAC_LENGTH,
        )

        version = ByteUtil.high_bits_to_int(message_parts[0][0])
        message = message_parts[1]

        if version != 3:
            raise InvalidMessageException("Unknown version: %s" % version)

        whisper_message = cast(
            WhisperMessageProto, whisper_pb2.WhisperMessage()  # pyright: ignore
        )
        whisper_message.ParseFromString(message)

        if not whisper_message.ciphertext or not whisper_message.ratchetKey:
            raise InvalidMessageException("Incomplete message")

        try:
            sender_ratchet_key = Curve.decode_point(whisper_message.ratchetKey)
            assert isinstance(sender_ratchet_key, CurvePublicKey)
        except InvalidKeyException as e:
            raise InvalidMessageException(str(e))

        return WhisperMessage(
            serialized,
            sender_ratchet_key,
            whisper_message.counter,
            whisper_message.previousCounter,
            whisper_message.ciphertext,
        )

    def get_sender_ratchet_key(self) -> CurvePublicKey:
        return self._sender_ratchet_key

    def get_message_version(self) -> int:
        return 3

    def get_counter(self) -> int:
        return self._counter

    def get_body(self) -> bytes:
        return self._ciphertext

    def verify_mac(
        self,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
        mac_key: bytes,
    ) -> None:
        parts = ByteUtil.split(
            self._serialized, len(self._serialized) - MAC_LENGTH, MAC_LENGTH
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
        mac.update(serialized)
        full_mac = mac.digest()
        return ByteUtil.trim(full_mac, MAC_LENGTH)

    def serialize(self) -> bytes:
        return self._serialized

    def get_type(self) -> int:
        return CiphertextMessage.WHISPER_TYPE


class WhisperMessageProto(google.protobuf.message.Message):
    ratchetKey: bytes
    counter: int
    previousCounter: int
    ciphertext: bytes
