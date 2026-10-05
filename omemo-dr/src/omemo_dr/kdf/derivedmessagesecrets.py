from ..util.byteutil import ByteUtil


class DerivedMessageSecrets:
    SIZE = 80
    CIPHER_KEY_LENGTH = 32
    MAC_KEY_LENGTH = 32
    IV_LENGTH = 16

    def __init__(self, okm: bytes) -> None:
        keys = ByteUtil.split(
            okm, self.CIPHER_KEY_LENGTH, self.MAC_KEY_LENGTH, self.IV_LENGTH
        )
        self._cipher_key = keys[0]  # AES
        self._mac_key = keys[1]  # sha256
        self._iv = keys[2]

    def get_cipher_key(self) -> bytes:
        return self._cipher_key

    def get_mac_key(self) -> bytes:
        return self._mac_key

    def get_iv(self) -> bytes:
        return self._iv
