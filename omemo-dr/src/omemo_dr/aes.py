from __future__ import annotations

from typing import NamedTuple

import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PKCS7

log = logging.getLogger(__name__)

IV_SIZE = 12


class EncryptionResult(NamedTuple):
    payload: bytes
    key: bytes
    iv: bytes


def _decrypt(key: bytes, iv: bytes, tag: bytes, data: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key), GCM(iv, tag=tag), backend=default_backend()
    ).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def aes_decrypt(_key: bytes, iv: bytes, payload: bytes) -> str:
    if len(_key) >= 32:
        # XEP-0384
        log.debug("XEP Compliant Key/Tag")
        data = payload
        key = _key[:16]
        tag = _key[16:]
    else:
        # Legacy
        log.debug("Legacy Key/Tag")
        data = payload[:-16]
        key = _key
        tag = payload[-16:]

    return _decrypt(key, iv, tag, data).decode()


def aes_decrypt_file(key: bytes, iv: bytes, payload: bytes) -> bytes:
    data = payload[:-16]
    tag = payload[-16:]
    return _decrypt(key, iv, tag, data)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    encryptor = Cipher(
        algorithms.AES(key), GCM(iv), backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag


def _encrypt(
    data: str | bytes, key_size: int, iv_size: int = IV_SIZE
) -> tuple[bytes, bytes, bytes, bytes]:
    if isinstance(data, str):
        data = data.encode()
    key = os.urandom(key_size)
    iv = os.urandom(iv_size)
    encryptor = Cipher(
        algorithms.AES(key), GCM(iv), backend=default_backend()
    ).encryptor()

    payload = encryptor.update(data) + encryptor.finalize()
    return key, iv, encryptor.tag, payload


def aes_encrypt(plaintext: str) -> EncryptionResult:
    key, iv, tag, payload = _encrypt(plaintext, 16)
    key += tag
    return EncryptionResult(payload=payload, key=key, iv=iv)


def aes_encrypt_file(data: bytes) -> EncryptionResult:
    (
        key,
        iv,
        tag,
        payload,
    ) = _encrypt(data, 32)
    payload += tag
    return EncryptionResult(payload=payload, key=key, iv=iv)


def get_new_key() -> bytes:
    return os.urandom(16)


def get_new_iv() -> bytes:
    return os.urandom(IV_SIZE)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv), backend=default_backend()
    ).encryptor()

    return encryptor.update(padded_plaintext) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv), backend=default_backend()
    ).decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def hmac_calculate(key: bytes, data: bytes) -> bytes:
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(data)
    return hmac.finalize()
