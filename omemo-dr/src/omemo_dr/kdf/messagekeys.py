class MessageKeys:
    def __init__(
        self, cipher_key: bytes, mac_key: bytes, iv: bytes, counter: int
    ) -> None:
        self._cipher_key = cipher_key
        self._mac_key = mac_key
        self._iv = iv
        self._counter = counter

    def get_cipher_key(self) -> bytes:
        return self._cipher_key

    def get_mac_key(self) -> bytes:
        return self._mac_key

    def get_iv(self) -> bytes:
        return self._iv

    def get_counter(self) -> int:
        return self._counter
