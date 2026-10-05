from .. import _curve  # pyright: ignore


def calculate_signature(random: bytes, privatekey: bytes, message: bytes) -> bytes:
    return _curve.calculateSignature(random, privatekey, message)  # pyright: ignore


def verify_signature_curve(publickey: bytes, message: bytes, signature: bytes) -> int:
    return _curve.verifySignatureCurve(publickey, message, signature)  # pyright: ignore


def verify_signature_ed(publickey: bytes, message: bytes, signature: bytes) -> int:
    return _curve.verifySignatureEd(publickey, message, signature)  # pyright: ignore


def generate_private_key(random: bytes) -> bytes:
    return _curve.generatePrivateKey(random)  # pyright: ignore


def generate_public_key(privatekey: bytes) -> bytes:
    return _curve.generatePublicKey(privatekey)  # pyright: ignore


def calculate_agreement(privatekey: bytes, publickey: bytes) -> bytes:
    return _curve.calculateAgreement(privatekey, publickey)  # pyright: ignore


def convert_curve_to_ed_pubkey(publickey: bytes) -> bytes:
    return _curve.convertCurveToEdPubkey(publickey)  # pyright: ignore


def convert_ed_to_curve_pubkey(publickey: bytes) -> bytes:
    return _curve.convertEdToCurvePubkey(publickey)  # pyright: ignore
