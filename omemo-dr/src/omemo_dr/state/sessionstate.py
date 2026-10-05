from __future__ import annotations

from typing import cast
from typing import Optional
from typing import Union

import google.protobuf.message

from ..ecc.curve import Curve
from ..ecc.djbec import CurvePublicKey
from ..ecc.eckeypair import ECKeyPair
from ..identitykeypair import IdentityKey
from ..kdf.messagekeys import MessageKeys
from ..ratchet.chainkey import ChainKey
from ..ratchet.rootkey import RootKey
from . import storage_pb2


class SessionState:
    def __init__(
        self, session: Optional[Union[SessionState, SessionStructureProto]] = None
    ) -> None:
        if session is None:
            self._session_structure = cast(
                SessionStructureProto, storage_pb2.SessionStructure()  # pyright: ignore
            )

        elif isinstance(session, SessionState):
            self._session_structure = cast(
                SessionStructureProto, storage_pb2.SessionStructure()  # pyright: ignore
            )
            self._session_structure.CopyFrom(session.get_structure())

        else:
            self._session_structure = session

    def get_structure(self) -> SessionStructureProto:
        return self._session_structure

    def get_alice_base_key(self) -> bytes:
        return self._session_structure.aliceBaseKey

    def set_alice_base_key(self, alice_base_key: bytes) -> None:
        self._session_structure.aliceBaseKey = alice_base_key

    def set_session_version(self, version: int) -> None:
        self._session_structure.sessionVersion = version

    def get_session_version(self) -> int:
        return self._session_structure.sessionVersion

    def set_remote_identity_key(self, identity_key: IdentityKey) -> None:
        self._session_structure.remoteIdentityPublic = identity_key.serialize()

    def set_local_identity_key(self, identity_key: IdentityKey) -> None:
        self._session_structure.localIdentityPublic = identity_key.serialize()

    def get_remote_identity_key(self) -> IdentityKey:
        assert self._session_structure.remoteIdentityPublic is not None
        return IdentityKey(self._session_structure.remoteIdentityPublic)

    def get_local_identity_key(self) -> IdentityKey:
        return IdentityKey(self._session_structure.localIdentityPublic)

    def get_previous_counter(self) -> int:
        return self._session_structure.previousCounter

    def set_previous_counter(self, previous_counter: int) -> None:
        self._session_structure.previousCounter = previous_counter

    def get_root_key(self) -> RootKey:
        return RootKey(
            self.get_session_version(),
            self._session_structure.rootKey,
        )

    def set_root_key(self, root_key: RootKey) -> None:
        self._session_structure.rootKey = root_key.get_key_bytes()

    def get_sender_ratchet_key(self) -> CurvePublicKey:
        key = Curve.decode_point(self._session_structure.senderChain.senderRatchetKey)
        assert isinstance(key, CurvePublicKey)
        return key

    def get_sender_ratchet_key_pair(self) -> ECKeyPair:
        public_key = self.get_sender_ratchet_key()
        private_key = Curve.decode_private_point(
            self._session_structure.senderChain.senderRatchetKeyPrivate
        )

        return ECKeyPair(public_key, private_key)

    def has_receiver_chain(
        self, ec_publick_key_sender_ephemeral: CurvePublicKey
    ) -> bool:
        return self.get_receiver_chain(ec_publick_key_sender_ephemeral) is not None

    def has_sender_chain(self) -> bool:
        return self._session_structure.HasField("senderChain")

    def get_receiver_chain(
        self, ec_publick_key_sender_ephemeral: CurvePublicKey
    ) -> Optional[tuple[ChainStructureProto, int]]:
        receiver_chains = self._session_structure.receiverChains

        for index, receiver_chain in enumerate(receiver_chains):
            chain_sender_ratchet_key = Curve.decode_point(
                receiver_chain.senderRatchetKey
            )
            if chain_sender_ratchet_key == ec_publick_key_sender_ephemeral:
                return (receiver_chain, index)

    def get_receiver_chain_key(
        self, ec_public_key_sender_ephemeral: CurvePublicKey
    ) -> ChainKey:
        receiver_chain_and_index = self.get_receiver_chain(
            ec_public_key_sender_ephemeral
        )
        assert receiver_chain_and_index is not None
        receiver_chain = receiver_chain_and_index[0]
        assert receiver_chain is not None

        return ChainKey(
            self.get_session_version(),
            receiver_chain.chainKey.key,
            receiver_chain.chainKey.index,
        )

    def add_receiver_chain(
        self, ec_publick_key_sender_ratchet_key: CurvePublicKey, chain_key: ChainKey
    ) -> None:
        sender_ratchet_key = ec_publick_key_sender_ratchet_key

        chain = cast(
            ChainStructureProto,
            storage_pb2.SessionStructure.Chain(),  # pyright: ignore
        )
        chain.senderRatchetKey = sender_ratchet_key.serialize()
        chain.chainKey.key = chain_key.get_key()
        chain.chainKey.index = chain_key.get_index()

        self._session_structure.receiverChains.extend([chain])

        if len(self._session_structure.receiverChains) > 5:
            del self._session_structure.receiverChains[0]

    def set_sender_chain(
        self, ec_key_pair_sender_ratchet_key_pair: ECKeyPair, chain_key: ChainKey
    ) -> None:
        sender_ratchet_key_pair = ec_key_pair_sender_ratchet_key_pair

        self._session_structure.senderChain.senderRatchetKey = (
            sender_ratchet_key_pair.get_public_key().serialize()
        )
        self._session_structure.senderChain.senderRatchetKeyPrivate = (
            sender_ratchet_key_pair.get_private_key().serialize()
        )
        self._session_structure.senderChain.chainKey.key = chain_key.get_key()
        self._session_structure.senderChain.chainKey.index = chain_key.get_index()

    def get_sender_chain_key(self) -> ChainKey:
        chain_key_structure = self._session_structure.senderChain.chainKey
        return ChainKey(
            self.get_session_version(),
            chain_key_structure.key,
            chain_key_structure.index,
        )

    def set_sender_chain_key(self, chain_key_next_chain_key: ChainKey) -> None:
        next_chain_key = chain_key_next_chain_key

        self._session_structure.senderChain.chainKey.key = next_chain_key.get_key()
        self._session_structure.senderChain.chainKey.index = next_chain_key.get_index()

    def has_message_keys(
        self, ec_publick_key_sender_ephemeral: CurvePublicKey, counter: int
    ) -> bool:
        sender_ephemeral = ec_publick_key_sender_ephemeral
        chain_and_index = self.get_receiver_chain(sender_ephemeral)
        assert chain_and_index is not None
        chain = chain_and_index[0]

        message_key_list = chain.messageKeys
        for message_key in message_key_list:
            if message_key.index == counter:
                return True

        return False

    def remove_message_keys(
        self, ec_public_key_sender_ephemeral: CurvePublicKey, counter: int
    ) -> MessageKeys:
        sender_ephemeral = ec_public_key_sender_ephemeral
        chain_and_index = self.get_receiver_chain(sender_ephemeral)
        assert chain_and_index is not None
        chain = chain_and_index[0]
        assert chain is not None

        message_key_list = chain.messageKeys
        result = None

        for i in range(0, len(message_key_list)):
            message_key = message_key_list[i]
            if message_key.index == counter:
                result = MessageKeys(
                    message_key.cipherKey,
                    message_key.macKey,
                    message_key.iv,
                    message_key.index,
                )
                del message_key_list[i]
                break

        assert result is not None

        self._session_structure.receiverChains[chain_and_index[1]].CopyFrom(chain)

        return result

    def set_message_keys(
        self, ec_public_key_sender_ephemeral: CurvePublicKey, message_keys: MessageKeys
    ) -> None:
        sender_ephemeral = ec_public_key_sender_ephemeral
        chain_and_index = self.get_receiver_chain(sender_ephemeral)
        assert chain_and_index is not None
        chain = chain_and_index[0]
        message_key_structure = chain.messageKeys.add()  # pyright: ignore
        message_key_structure.cipherKey = message_keys.get_cipher_key()
        message_key_structure.macKey = message_keys.get_mac_key()
        message_key_structure.index = message_keys.get_counter()
        message_key_structure.iv = message_keys.get_iv()

        self._session_structure.receiverChains[chain_and_index[1]].CopyFrom(chain)

    def set_receiver_chain_key(
        self, ec_public_key_sender_ephemeral: CurvePublicKey, chain_key: ChainKey
    ) -> None:
        sender_ephemeral = ec_public_key_sender_ephemeral
        chain_and_index = self.get_receiver_chain(sender_ephemeral)
        assert chain_and_index is not None
        chain = chain_and_index[0]
        chain.chainKey.key = chain_key.get_key()
        chain.chainKey.index = chain_key.get_index()

        self._session_structure.receiverChains[chain_and_index[1]].CopyFrom(chain)

    def set_unacknowledged_pre_key_message(
        self,
        pre_key_id: int,
        signed_pre_key_id: int,
        base_key: CurvePublicKey,
        pq_signed_pre_key_id: int,
        kem_ciphertext: bytes,
    ) -> None:
        self._session_structure.pendingPreKey.signedPreKeyId = signed_pre_key_id
        self._session_structure.pendingPreKey.baseKey = base_key.serialize()
        self._session_structure.pendingPreKey.preKeyId = pre_key_id
        self._session_structure.pendingPreKey.pqSignedPreKeyId = pq_signed_pre_key_id
        self._session_structure.pendingPreKey.kemCiphertext = kem_ciphertext

    def has_unacknowledged_pre_key_message(self) -> bool:
        return self._session_structure.HasField("pendingPreKey")

    def get_unacknowledged_pre_key_message_items(
        self,
    ) -> UnacknowledgedPreKeyMessageItems:
        pre_key_id = None
        if self._session_structure.pendingPreKey.HasField("preKeyId"):
            pre_key_id = self._session_structure.pendingPreKey.preKeyId

        assert pre_key_id is not None
        return UnacknowledgedPreKeyMessageItems(
            pre_key_id,
            self._session_structure.pendingPreKey.signedPreKeyId,
            Curve.decode_point(self._session_structure.pendingPreKey.baseKey),
            self._session_structure.pendingPreKey.pqSignedPreKeyId,
            self._session_structure.pendingPreKey.kemCiphertext,
        )

    def clear_unacknowledged_pre_key_message(self) -> None:
        self._session_structure.ClearField("pendingPreKey")

    def set_remote_device_id(self, device_id: int) -> None:
        self._session_structure.remoteRegistrationId = device_id

    def get_remote_device_id(self) -> int:
        return self._session_structure.remoteRegistrationId

    def set_our_device_id(self, device_id: int) -> None:
        self._session_structure.localRegistrationId = device_id

    def get_our_device_id(self) -> int:
        return self._session_structure.localRegistrationId

    def serialize(self) -> bytes:
        return self._session_structure.SerializeToString()


class UnacknowledgedPreKeyMessageItems:
    def __init__(
        self,
        pre_key_id: int,
        signed_pre_key_id: int,
        base_key: CurvePublicKey,
        pq_signed_pre_key_id: int,
        kem_ciphertext: bytes,
    ) -> None:
        self._pre_key_id = pre_key_id
        self._signed_pre_key_id = signed_pre_key_id
        self._base_key = base_key
        self._pq_signed_pre_key_id = pq_signed_pre_key_id
        self._kem_ciphertext = kem_ciphertext

    def get_pre_key_id(self) -> int:
        return self._pre_key_id

    def get_signed_pre_key_id(self) -> int:
        return self._signed_pre_key_id

    def get_base_key(self) -> CurvePublicKey:
        return self._base_key

    def get_pq_signed_pre_key_id(self) -> int:
        return self._pq_signed_pre_key_id

    def get_kem_ciphertext(self) -> bytes:
        return self._kem_ciphertext


class MessageKeyStructureProto(google.protobuf.message.Message):
    index: int
    cipherKey: bytes
    macKey: bytes
    iv: bytes


class ChainKeyStructureProto(google.protobuf.message.Message):
    index: int
    key: bytes


class ChainStructureProto(google.protobuf.message.Message):
    senderRatchetKey: bytes
    senderRatchetKeyPrivate: bytes
    chainKey: ChainKeyStructureProto
    messageKeys: list[MessageKeyStructureProto]


class PendingKeyExchangeStructureProto(google.protobuf.message.Message):
    sequence: int
    localBaseKey: bytes
    localBaseKeyPrivate: bytes
    localRatchetKey: bytes
    localRatchetKeyPrivate: bytes
    localIdentityKey: bytes
    localIdentityKeyPrivate: bytes


class PendingPreKeyStructureProto(google.protobuf.message.Message):
    preKeyId: int
    signedPreKeyId: int
    baseKey: bytes
    pqSignedPreKeyId: int
    kemCiphertext: bytes


class SessionStructureProto(google.protobuf.message.Message):
    sessionVersion: int
    localIdentityPublic: bytes
    remoteIdentityPublic: bytes
    rootKey: bytes
    previousCounter: int
    senderChain: ChainStructureProto
    receiverChains: list[ChainStructureProto]
    pendingKeyExchange: PendingKeyExchangeStructureProto
    pendingPreKey: PendingPreKeyStructureProto
    remoteRegistrationId: int
    localRegistrationId: int
    needsRefresh: bool
    aliceBaseKey: bytes
