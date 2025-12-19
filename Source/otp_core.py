import os
import hashlib

class OTP:
    @staticmethod
    def generate_key(length: int) -> bytes:
        return os.urandom(length)

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def encrypt(data: bytes) -> tuple[bytes, bytes]:
        key = OTP.generate_key(len(data))
        ciphertext = OTP.xor_bytes(data, key)
        return ciphertext, key

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        return OTP.xor_bytes(ciphertext, key)

    @staticmethod
    def split_key(key: bytes) -> tuple[bytes, bytes, str]:
        r = OTP.generate_key(len(key))
        part1 = r
        part2 = OTP.xor_bytes(key, r)
        key_hash = hashlib.sha256(key).hexdigest()
        return part1, part2, key_hash


