from __future__ import annotations

from .djbec import CurvePublicKey
from .djbec import DjbECPrivateKey


class ECKeyPair:
    def __init__(
        self, public_key: CurvePublicKey, private_key: DjbECPrivateKey
    ) -> None:
        self._public_key = public_key
        self._private_key = private_key

    def get_private_key(self) -> DjbECPrivateKey:
        return self._private_key

    def get_public_key(self) -> CurvePublicKey:
        return self._public_key
