from glob import glob

from setuptools import Extension
from setuptools import setup

sources = ["curve25519/curve25519module.c", "curve25519/curve/curve25519-donna.c"]
sources.extend(glob("curve25519/curve/ed25519/*.c"))
sources.extend(glob("curve25519/curve/ed25519/additions/*.c"))
sources.extend(glob("curve25519/curve/ed25519/nacl_sha512/*.c"))

setup(
    ext_modules=[
        Extension(
            name="omemo_dr._curve",
            sources=sorted(sources),
            include_dirs=[
                "curve25519/curve/ed25519/nacl_includes",
                "curve25519/curve/ed25519/additions",
                "curve25519/curve/ed25519",
            ],
        ),
    ]
)
