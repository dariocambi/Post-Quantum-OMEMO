from ..util.byteutil import ByteUtil


class DerivedRootSecrets:
    SIZE = 64

    def __init__(self, okm: bytes) -> None:
        keys = ByteUtil.split(okm, 32, 32)
        self._root_key = keys[0]
        self._chain_key = keys[1]

    def get_root_key(self) -> bytes:
        return self._root_key

    def get_chain_key(self) -> bytes:
        return self._chain_key
