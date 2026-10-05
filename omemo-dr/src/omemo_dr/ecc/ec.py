import abc


class ECPublicKey(abc.ABC):
    @abc.abstractmethod
    def serialize(self) -> bytes:
        pass


class ECPrivateKey(abc.ABC):
    @abc.abstractmethod
    def serialize(self) -> bytes:
        pass
