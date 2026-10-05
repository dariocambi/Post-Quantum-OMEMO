from __future__ import annotations

import logging

from ..const import PQ_KEM_SHARED_SECRET_LENGTH
from ..ecc.curve import Curve
from ..ecc.djbec import CurvePublicKey
from ..exceptions import HybridKeyAgreementError
from ..kdf import hkdf
from ..pqkem.kem import KEM
from ..state.sessionstate import SessionState
from ..util.byteutil import ByteUtil
from .aliceparameters import AliceParameters
from .bobparameters import BobParameters
from .chainkey import ChainKey
from .rootkey import RootKey

log = logging.getLogger(__name__)

# 32 discontinuity bytes + four 32-byte X25519 agreements + the KEM secret.
HYBRID_MASTER_SECRET_LENGTH = 32 + 4 * 32 + PQ_KEM_SHARED_SECRET_LENGTH


class RatchetingSession:
    @staticmethod
    def initialize_session_as_alice(
        session_state: SessionState,
        session_version: int,
        parameters: AliceParameters,
    ) -> bytes:
        session_state.set_session_version(session_version)
        session_state.set_remote_identity_key(parameters.get_their_identity_key())
        session_state.set_local_identity_key(
            parameters.get_our_identity_key().get_public_key()
        )

        sending_ratchet_key = Curve.generate_key_pair()
        secrets = bytearray()

        secrets.extend(RatchetingSession.get_discontinuity_bytes())

        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_signed_pre_key(),
                parameters.get_our_identity_key().get_private_key(),
            )
        )
        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_identity_key().get_public_key(),
                parameters.get_our_base_key().get_private_key(),
            )
        )
        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_signed_pre_key(),
                parameters.get_our_base_key().get_private_key(),
            )
        )

        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_one_time_pre_key(),
                parameters.get_our_base_key().get_private_key(),
            )
        )

        # --- The KEM encapsulation step. This is the post-quantum part of the hybrid key agreement. ---
        kem_ciphertext, kem_shared_secret = KEM.encapsulate(
            parameters.get_their_pq_signed_pre_key()
        )
        secrets.extend(kem_shared_secret)

        if len(secrets) != HYBRID_MASTER_SECRET_LENGTH:
            raise HybridKeyAgreementError(f'Hybrid master secret is {len(secrets)} bytes, expected {HYBRID_MASTER_SECRET_LENGTH}')

        log.info(f"Hybrid X3DH: classical=128B kem={len(kem_shared_secret)}B total={len(secrets)}B")

        derived_keys = RatchetingSession.calculate_derived_keys(
            session_version, bytes(secrets), hybrid=True
        )
        sending_chain = derived_keys.get_root_key().create_chain(
            parameters.get_their_ratchet_key(), sending_ratchet_key
        )

        session_state.add_receiver_chain(
            parameters.get_their_ratchet_key(), derived_keys.get_chain_key()
        )
        session_state.set_sender_chain(sending_ratchet_key, sending_chain[1])
        session_state.set_root_key(sending_chain[0])

        return kem_ciphertext

    @staticmethod
    def initialize_session_as_bob(
        session_state: SessionState,
        session_version: int,
        parameters: BobParameters,
    ) -> None:
        session_state.set_session_version(session_version)
        session_state.set_remote_identity_key(parameters.get_their_identity_key())
        session_state.set_local_identity_key(
            parameters.get_our_identity_key().get_public_key()
        )

        secrets = bytearray()

        secrets.extend(RatchetingSession.get_discontinuity_bytes())

        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_identity_key().get_public_key(),
                parameters.get_our_signed_pre_key().get_private_key(),
            )
        )

        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_base_key(),
                parameters.get_our_identity_key().get_private_key(),
            )
        )
        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_base_key(),
                parameters.get_our_signed_pre_key().get_private_key(),
            )
        )

        our_one_time_pre_key = parameters.get_our_one_time_pre_key()
        secrets.extend(
            Curve.calculate_agreement(
                parameters.get_their_base_key(),
                our_one_time_pre_key.get_private_key(),
            )
        )

        # --- The KEM decapsulation step. This is the post-quantum part of the hybrid key agreement. ---
        kem_shared_secret = KEM.decapsulate(
            parameters.get_our_pq_signed_pre_key().get_private_key(),
            parameters.get_kem_ciphertext(),
        )
        secrets.extend(kem_shared_secret)

        if len(secrets) != HYBRID_MASTER_SECRET_LENGTH:
            raise HybridKeyAgreementError(f'Hybrid master secret is {len(secrets)} bytes, expected {HYBRID_MASTER_SECRET_LENGTH}')

        log.info(f"Hybrid X3DH: classical=128B kem={len(kem_shared_secret)}B total={len(secrets)}B")

        derived_keys = RatchetingSession.calculate_derived_keys(
            session_version, bytes(secrets), hybrid=True
        )
        session_state.set_sender_chain(
            parameters.get_our_ratchet_key(), derived_keys.get_chain_key()
        )
        session_state.set_root_key(derived_keys.get_root_key())

    @staticmethod
    def get_discontinuity_bytes() -> bytearray:
        return bytearray([0xFF] * 32)

    @staticmethod
    def calculate_derived_keys(
        session_version: int, master_secret: bytes, *, hybrid: bool = False
    ) -> DerivedKeys:
        if hybrid:
            domain_separator = "PQOMEMO Hybrid Payload v1"
        elif session_version <= 3:
            domain_separator = "WhisperText"
        else:
            domain_separator = "OMEMO Payload"

        derived_secret_bytes = hkdf.derive(
            input_key_material=master_secret,
            length=64,
            salt=bytes(32),
            info=domain_separator.encode(),
        )
        derived_secrets = ByteUtil.split(derived_secret_bytes, 32, 32)

        return RatchetingSession.DerivedKeys(
            RootKey(session_version, derived_secrets[0]),
            ChainKey(session_version, derived_secrets[1], 0),
        )

    @staticmethod
    def is_alice(our_key: CurvePublicKey, their_key: CurvePublicKey) -> bool:
        return our_key < their_key

    class DerivedKeys:
        def __init__(self, root_key: RootKey, chain_key: ChainKey):
            self._root_key = root_key
            self._chain_key = chain_key

        def get_root_key(self):
            return self._root_key

        def get_chain_key(self):
            return self._chain_key
