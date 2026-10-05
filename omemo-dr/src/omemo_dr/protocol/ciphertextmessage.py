import abc


class CiphertextMessage(abc.ABC):
    SUPPORTED_VERSIONS = (3, 4)
    CURRENT_VERSION = 3

    WHISPER_TYPE = 2
    PREKEY_TYPE = 3
    SENDERKEY_TYPE = 4
    SENDERKEY_DISTRIBUTION_TYPE = 5

    # This should be the worst case (worse than V2).
    # So not always accurate, but good enough for padding.
    ENCRYPTED_MESSAGE_OVERHEAD = 53

    @abc.abstractmethod
    def serialize(self) -> bytes:
        return b""

    @abc.abstractmethod
    def get_type(self) -> int:
        return 0
