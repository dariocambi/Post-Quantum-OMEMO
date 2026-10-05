from __future__ import annotations

import hashlib
import hmac

from ..kdf import hkdf
from ..kdf.derivedmessagesecrets import DerivedMessageSecrets
from ..kdf.messagekeys import MessageKeys

MESSAGE_KEY_SEED = bytes([0x01])
CHAIN_KEY_SEED = bytes([0x02])


class ChainKey:
    def __init__(self, session_version: int, key: bytes, index: int) -> None:
        self._session_version = session_version
        self._key = key
        self._index = index

    def get_key(self) -> bytes:
        return self._key

    def get_index(self) -> int:
        return self._index

    def get_next_chain_key(self) -> ChainKey:
        nextKey = self.get_base_material(CHAIN_KEY_SEED)
        return ChainKey(self._session_version, nextKey, self._index + 1)

    def get_message_keys(self) -> MessageKeys:
        if self._session_version == 3:
            domain_separator = "WhisperMessageKeys"
        elif self._session_version == 4:
            domain_separator = "OMEMO Message Key Material"
        else:
            raise ValueError("Invalid session version: %s", self._session_version)

        input_key_material = self.get_base_material(MESSAGE_KEY_SEED)
        key_material_bytes = hkdf.derive(
            input_key_material=input_key_material,
            length=DerivedMessageSecrets.SIZE,
            salt=bytes(32),
            info=domain_separator.encode(),
        )
        key_material = DerivedMessageSecrets(key_material_bytes)

        return MessageKeys(
            key_material.get_cipher_key(),
            key_material.get_mac_key(),
            key_material.get_iv(),
            self._index,
        )

    def get_base_material(self, seedBytes: bytes) -> bytes:
        mac = hmac.new(bytes(self._key), digestmod=hashlib.sha256)
        mac.update(bytes(seedBytes))
        return mac.digest()
