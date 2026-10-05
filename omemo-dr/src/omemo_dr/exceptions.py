from __future__ import annotations

from typing import Any
from typing import Optional


class DuplicateMessageException(Exception):
    pass


class InvalidKeyException(Exception):
    pass


class InvalidKeyIdException(Exception):
    pass


class InvalidMessageException(Exception):
    def __init__(self, message: str, exceptions: Optional[list[Exception]] = None):
        if exceptions:
            message += str(exceptions[0])
        super(InvalidMessageException, self).__init__(message)


class InvalidVersionException(Exception):
    pass


class NoSessionException(Exception):
    pass


class UntrustedIdentityException(Exception):
    def __init__(self, name: str, identityKey: Any):
        self.name = name
        self.identityKey = identityKey

    def getName(self) -> str:
        return self.name

    def getIdentityKey(self) -> Any:
        return self.identityKey


class NoDevicesFound(Exception):
    pass


class NoValidSessions(Exception):
    pass


class SelfMessage(Exception):
    pass


class MessageNotForDevice(Exception):
    pass


class DecryptionFailed(Exception):
    pass


class KeyExchangeMessage(Exception):
    pass


class InvalidMessage(Exception):
    pass


class DuplicateMessage(Exception):
    pass


class BundleValidationError(Exception):
    pass


class HybridKeyAgreementError(Exception):
    pass
