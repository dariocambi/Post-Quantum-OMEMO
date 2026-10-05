from __future__ import annotations

from ..ecc.djbec import CurvePublicKey
from ..ecc.eckeypair import ECKeyPair
from ..identitykey import IdentityKey
from ..identitykeypair import IdentityKeyPair
from ..pqkem.keys import KemPublicKey


class AliceParameters:
    def __init__(
        self,
        our_identity_key: IdentityKeyPair,
        our_base_key: ECKeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: CurvePublicKey,
        their_ratchet_key: CurvePublicKey,
        their_one_time_pre_key: CurvePublicKey,
        their_pq_signed_pre_key: KemPublicKey,
        their_pq_signed_pre_key_id: int,
    ) -> None:
        self._our_base_key = our_base_key
        self._our_identity_key = our_identity_key
        self._their_signed_pre_key = their_signed_pre_key
        self._their_ratchet_key = their_ratchet_key
        self._their_identity_key = their_identity_key
        self._their_one_time_pre_key = their_one_time_pre_key
        self._their_pq_signed_pre_key = their_pq_signed_pre_key
        self._their_pq_signed_pre_key_id = their_pq_signed_pre_key_id

    def get_our_identity_key(self) -> IdentityKeyPair:
        return self._our_identity_key

    def get_our_base_key(self) -> ECKeyPair:
        return self._our_base_key

    def get_their_identity_key(self) -> IdentityKey:
        return self._their_identity_key

    def get_their_signed_pre_key(self) -> CurvePublicKey:
        return self._their_signed_pre_key

    def get_their_one_time_pre_key(self) -> CurvePublicKey:
        return self._their_one_time_pre_key

    def get_their_ratchet_key(self) -> CurvePublicKey:
        return self._their_ratchet_key

    def get_their_pq_signed_pre_key(self) -> KemPublicKey:
        return self._their_pq_signed_pre_key

    def get_their_pq_signed_pre_key_id(self) -> int:
        return self._their_pq_signed_pre_key_id
