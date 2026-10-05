from __future__ import annotations

from ..ecc.curve import Curve
from ..ecc.djbec import CurvePublicKey
from ..ecc.eckeypair import ECKeyPair
from ..kdf import hkdf
from ..kdf.derivedrootsecrets import DerivedRootSecrets
from .chainkey import ChainKey


class RootKey:
    def __init__(self, session_version: int, key: bytes) -> None:
        self._session_version = session_version
        self._key = key

    def get_key_bytes(self) -> bytes:
        return self._key

    def create_chain(
        self,
        ec_public_key_their_ratchet_key: CurvePublicKey,
        ec_key_pair_our_ratchet_key: ECKeyPair,
    ) -> tuple[RootKey, ChainKey]:
        if self._session_version == 3:
            domain_separator = "WhisperRatchet"
        elif self._session_version == 4:
            domain_separator = "OMEMO Root Chain"
        else:
            raise ValueError("Invalid session version: %s", self._session_version)

        shared_secret = Curve.calculate_agreement(
            ec_public_key_their_ratchet_key,
            ec_key_pair_our_ratchet_key.get_private_key(),
        )

        derived_secret_bytes = hkdf.derive(
            input_key_material=shared_secret,
            length=DerivedRootSecrets.SIZE,
            salt=self._key,
            info=domain_separator.encode(),
        )

        derived_secrets = DerivedRootSecrets(derived_secret_bytes)
        new_root_key = RootKey(self._session_version, derived_secrets.get_root_key())
        new_chain_key = ChainKey(
            self._session_version, derived_secrets.get_chain_key(), 0
        )
        return (new_root_key, new_chain_key)
