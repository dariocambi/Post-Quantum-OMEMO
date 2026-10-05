from __future__ import annotations

from typing import Optional

import abc

from ..const import OMEMOTrust
from ..identitykey import IdentityKey
from ..identitykeypair import IdentityKeyPair
from ..state.prekeyrecord import PreKeyRecord
from ..structs import IdentityInfo
from .pqsignedprekeyrecord import PqSignedPreKeyRecord
from .sessionrecord import SessionRecord
from .signedprekeyrecord import SignedPreKeyRecord


class Store(abc.ABC):
    # Secret

    @abc.abstractmethod
    def set_our_identity(
        self, device_id: int, identity_key_pair: IdentityKeyPair
    ) -> None:
        pass

    @abc.abstractmethod
    def get_identity_key_pair(self) -> IdentityKeyPair:
        pass

    @abc.abstractmethod
    def get_our_device_id(self) -> int:
        pass

    # Identity

    @abc.abstractmethod
    def save_identity(self, recipient_id: str, identity_key: IdentityKey) -> None:
        pass

    @abc.abstractmethod
    def delete_identity(self, recipient_id: str, identity_key: IdentityKey) -> None:
        pass

    @abc.abstractmethod
    def is_trusted_identity(self, recipient_id: str, identity_key: IdentityKey) -> bool:
        pass

    @abc.abstractmethod
    def set_trust(
        self, recipient_id: str, identity_key: IdentityKey, trust: OMEMOTrust
    ) -> None:
        pass

    @abc.abstractmethod
    def set_identity_last_seen(
        self, recipient_id: str, identity_key: IdentityKey
    ) -> None:
        pass

    @abc.abstractmethod
    def get_identity_infos(self, recipient_ids: str | list[str]) -> list[IdentityInfo]:
        pass

    # Pre Keys

    @abc.abstractmethod
    def get_pre_key_count(self) -> int:
        pass

    @abc.abstractmethod
    def load_pre_key(self, pre_key_id: int) -> PreKeyRecord:
        pass

    @abc.abstractmethod
    def load_pending_pre_keys(self) -> list[PreKeyRecord]:
        pass

    @abc.abstractmethod
    def get_current_pre_key_id(self) -> Optional[int]:
        pass

    @abc.abstractmethod
    def store_pre_key(self, pre_key_id: int, pre_key_record: PreKeyRecord):
        pass

    @abc.abstractmethod
    def contains_pre_key(self, pre_key_id: int) -> bool:
        pass

    @abc.abstractmethod
    def remove_pre_key(self, pre_key_id: int) -> None:
        pass

    # Signed Pre Key

    @abc.abstractmethod
    def load_signed_pre_key(self, signed_pre_key_id: int) -> SignedPreKeyRecord:
        pass

    @abc.abstractmethod
    def load_signed_pre_keys(self) -> list[SignedPreKeyRecord]:
        pass

    @abc.abstractmethod
    def store_signed_pre_key(
        self, signed_pre_key_id: int, signed_pre_key_record: SignedPreKeyRecord
    ) -> None:
        pass

    @abc.abstractmethod
    def contains_signed_pre_key(self, signed_pre_key_id: int) -> bool:
        pass

    @abc.abstractmethod
    def get_current_signed_pre_key_id(self) -> int:
        pass

    @abc.abstractmethod
    def get_signed_pre_key_timestamp(self, signed_pre_key_id: int) -> int:
        pass

    @abc.abstractmethod
    def remove_old_signed_pre_keys(self, timestamp: int) -> None:
        pass

    @abc.abstractmethod
    def remove_signed_pre_key(self, signed_pre_key_id: int) -> None:
        pass

    # PQ Signed Pre Key

    @abc.abstractmethod
    def load_pq_signed_pre_key(self, pq_signed_pre_key_id: int) -> PqSignedPreKeyRecord:
        pass

    @abc.abstractmethod
    def store_pq_signed_pre_key(
        self, pq_signed_pre_key_id: int, record: PqSignedPreKeyRecord
    ) -> None:
        pass

    @abc.abstractmethod
    def get_current_pq_signed_pre_key_id(self) -> int:
        pass

    @abc.abstractmethod
    def get_pq_signed_pre_key_timestamp(self, pq_signed_pre_key_id: int) -> int:
        pass

    @abc.abstractmethod
    def remove_old_pq_signed_pre_keys(self, timestamp: int) -> None:
        pass

    # Session

    @abc.abstractmethod
    def load_session(self, recipient_id: str, device_id: int) -> SessionRecord:
        pass

    @abc.abstractmethod
    def store_session(
        self, recipient_id: str, device_id: int, session_record: SessionRecord
    ) -> None:
        pass

    @abc.abstractmethod
    def contains_session(self, recipient_id: str, device_id: int) -> bool:
        pass

    @abc.abstractmethod
    def get_inactive_sessions_keys(self, recipient_id: str) -> list[IdentityKey]:
        pass

    @abc.abstractmethod
    def delete_session(self, recipient_id: str, device_id: int) -> None:
        pass

    @abc.abstractmethod
    def delete_all_sessions(self, recipient_id: str) -> None:
        pass

    # Others

    @abc.abstractmethod
    def get_active_device_tuples(self) -> list[tuple[str, int]]:
        pass

    @abc.abstractmethod
    def get_trust_for_identity(
        self, recipient_id: str, identity_key: IdentityKey
    ) -> Optional[OMEMOTrust]:
        pass

    @abc.abstractmethod
    def get_unacknowledged_count(self, recipient_id: str, device_id: int) -> int:
        pass

    @abc.abstractmethod
    def set_active_state(self, address: str, devicelist: list[int]) -> None:
        pass

    @abc.abstractmethod
    def set_inactive(self, address: str, device_id: int) -> None:
        pass

    @abc.abstractmethod
    def is_trusted(self, recipient_id: str, device_id: int) -> bool:
        pass

    @abc.abstractmethod
    def needs_init(self) -> bool:
        pass
