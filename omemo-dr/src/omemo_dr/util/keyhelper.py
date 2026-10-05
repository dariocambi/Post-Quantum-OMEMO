from __future__ import annotations

import random
import time

from ..const import MAX_INT
from ..const import PQ_PREKEY_SIGNATURE_CONTEXT
from ..ecc.curve import Curve
from ..identitykey import IdentityKey
from ..identitykeypair import IdentityKeyPair
from ..pqkem.kem import KEM
from ..state.pqsignedprekeyrecord import PqSignedPreKeyRecord
from ..state.prekeyrecord import PreKeyRecord
from ..state.signedprekeyrecord import SignedPreKeyRecord


class KeyHelper:
    @staticmethod
    def generate_identity_key_pair() -> IdentityKeyPair:
        """
        Generate an identity key pair. Clients should only do this once,
        at install time.
        @return the generated IdentityKeyPair.
        """
        key_pair = Curve.generate_key_pair()
        public_key = IdentityKey(key_pair.get_public_key())
        identity_key_pair = IdentityKeyPair.new(public_key, key_pair.get_private_key())
        return identity_key_pair

    @staticmethod
    def get_random_int() -> int:
        return random.randint(1, MAX_INT)

    @staticmethod
    def generate_pre_keys(start: int, count: int) -> list[PreKeyRecord]:
        """
        Generate a list of PreKeys.  Clients should do this at install time, and
        subsequently any time the list of PreKeys stored on the server runs low.

        PreKey IDs are shorts, so they will eventually be repeated.
        Clients should store PreKeys in a circular buffer, so that they are
        repeated as infrequently as possible.
        """
        results: list[PreKeyRecord] = []
        start -= 1
        for i in range(0, count):
            pre_key_id = ((start + i) % MAX_INT) + 1
            results.append(PreKeyRecord.new(pre_key_id, Curve.generate_key_pair()))

        return results

    @staticmethod
    def generate_signed_pre_key(
        identity_key_pair: IdentityKeyPair, signed_pre_key_id: int
    ) -> SignedPreKeyRecord:
        key_pair = Curve.generate_key_pair()
        signature = Curve.calculate_signature(
            identity_key_pair.get_private_key(), key_pair.get_public_key().serialize()
        )

        spk = SignedPreKeyRecord.new(
            signed_pre_key_id, int(round(time.time() * 1000)), key_pair, signature
        )

        return spk

    @staticmethod
    def generate_pq_signed_pre_key(
        identity_key_pair: IdentityKeyPair, pq_signed_pre_key_id: int
    ) -> PqSignedPreKeyRecord:
        key_pair = KEM.generate_key_pair()
        signature = Curve.calculate_signature(
            identity_key_pair.get_private_key(),
            PQ_PREKEY_SIGNATURE_CONTEXT + key_pair.get_public_key().serialize()
        )

        pqspk = PqSignedPreKeyRecord.new(
            pq_signed_pre_key_id, int(round(time.time() * 1000)), key_pair, signature
        )

        return pqspk

    @staticmethod
    def get_next_signed_pre_key_id(current_id: int) -> int:
        return current_id % MAX_INT + 1
