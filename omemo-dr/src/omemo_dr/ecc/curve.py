from __future__ import annotations

from typing import Union

import os

from .. import curve
from .djbec import CurvePublicKey
from .djbec import DjbECPrivateKey
from .djbec import EdPublicKey
from .eckeypair import ECKeyPair


class Curve:
    @staticmethod
    def _generate_private_key() -> bytes:
        rand = os.urandom(32)
        return curve.generate_private_key(rand)

    @staticmethod
    def _generate_public_key(private_key: bytes) -> bytes:
        return curve.generate_public_key(private_key)

    @staticmethod
    def generate_key_pair() -> ECKeyPair:
        private_key = Curve._generate_private_key()
        public_key = Curve._generate_public_key(private_key)
        return ECKeyPair(CurvePublicKey(public_key), DjbECPrivateKey(private_key))

    @staticmethod
    def decode_point(bytes_: bytes) -> CurvePublicKey:
        return CurvePublicKey.from_bytes(bytes_)

    @staticmethod
    def decode_private_point(_bytes: bytes) -> DjbECPrivateKey:
        return DjbECPrivateKey(_bytes)

    @staticmethod
    def calculate_agreement(
        public_key: CurvePublicKey, private_key: DjbECPrivateKey
    ) -> bytes:
        return curve.calculate_agreement(
            private_key.get_private_key(), public_key.get_bytes()
        )

    @staticmethod
    def verify_signature(
        ec_public_signing_key: Union[CurvePublicKey, EdPublicKey],
        message: bytes,
        signature: bytes,
    ) -> bool:
        if isinstance(ec_public_signing_key, CurvePublicKey):
            result = curve.verify_signature_curve(
                ec_public_signing_key.get_bytes(), message, signature
            )
        else:
            result = curve.verify_signature_ed(
                ec_public_signing_key.get_bytes(), message, signature
            )
        return result == 0

    @staticmethod
    def calculate_signature(
        private_signing_key: DjbECPrivateKey, message: bytes
    ) -> bytes:
        rand = os.urandom(64)
        return curve.calculate_signature(
            rand, private_signing_key.get_private_key(), message
        )
