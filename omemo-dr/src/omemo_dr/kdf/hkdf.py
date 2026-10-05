from __future__ import annotations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import hkdf


def derive(
    *,
    input_key_material: bytes,
    length: int,
    salt: bytes,
    info: bytes,
) -> bytes:
    return hkdf.HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    ).derive(input_key_material)
