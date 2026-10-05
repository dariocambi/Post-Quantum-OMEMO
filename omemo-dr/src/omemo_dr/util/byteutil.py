from __future__ import annotations

from typing import Optional


class ByteUtil:
    @staticmethod
    def combine(*args: int | list[int] | bytes | bytearray) -> bytes:
        baos = bytearray()
        for v in args:
            if isinstance(v, (list, bytes, bytearray)):
                baos.extend(v)
            else:
                baos.append(v)

        return bytes(baos)

    @staticmethod
    def split(
        inp: bytes,
        first_length: int,
        second_length: int,
        third_length: Optional[int] = None,
    ) -> list[bytes]:
        parts: list[bytes] = []
        parts.append(inp[:first_length])
        parts.append(inp[first_length : first_length + second_length])
        if third_length is not None:
            start = first_length + second_length
            end = first_length + second_length + third_length
            parts.append(inp[start:end])

        return parts

    @staticmethod
    def trim(inp: bytes, length: int) -> bytes:
        return inp[:length]

    @staticmethod
    def ints_to_byte_high_and_low(high_value: int, low_value: int) -> int:
        return ((high_value << 4 | low_value) & 0xFF) % 256

    @staticmethod
    def high_bits_to_int(value: int) -> int:
        return (value & 0xFF) >> 4
