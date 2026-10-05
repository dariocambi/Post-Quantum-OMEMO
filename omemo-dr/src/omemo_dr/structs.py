from __future__ import annotations

from typing import Protocol
from typing import TypedDict

import random
from dataclasses import dataclass

from .const import OMEMOTrust
from .identitykey import IdentityKey


@dataclass
class IdentityInfo:
    active: bool
    address: str
    device_id: int
    label: str
    last_seen: float | None
    public_key: IdentityKey
    trust: OMEMOTrust


@dataclass
class OMEMOConfig:
    default_prekey_amount: int
    min_prekey_amount: int
    spk_archive_seconds: int
    spk_cycle_seconds: int
    unacknowledged_count: int


class PreKey(TypedDict):
    key: bytes
    id: int


class OMEMOBundleProto(Protocol):
    device_id: int
    ik: bytes
    namespace: str
    otpks: list[PreKey]
    spk: PreKey
    spk_signature: bytes
    pqspk: PreKey           # Post-quantum signed pre-key
    pqspk_signature: bytes  # Signature of the post-quantum signed pre-key

    def pick_prekey(self) -> PreKey:
        ...


@dataclass
class OMEMOBundle(OMEMOBundleProto):
    device_id: int
    ik: bytes
    namespace: str
    otpks: list[PreKey]
    spk: PreKey
    spk_signature: bytes
    pqspk: PreKey           # Post-quantum signed pre-key
    pqspk_signature: bytes  # Signature of the post-quantum signed pre-key

    def pick_prekey(self) -> PreKey:
        return random.SystemRandom().choice(self.otpks)


@dataclass
class OMEMOMessageProto(Protocol):
    sid: int
    iv: bytes
    keys: dict[int, tuple[bytes, bool]]
    payload: bytes | None


@dataclass
class OMEMOMessage(OMEMOMessageProto):
    sid: int
    iv: bytes
    keys: dict[int, tuple[bytes, bool]]
    payload: bytes | None
