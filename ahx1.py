"""
ahx1 — Zero-password AEAD transport
====================================
Root entropy only. No user passphrase.
Intended production root source: TPM 2.0 / Secure Enclave / hardware keystore.

Design goals
------------
- Authenticated encryption (ChaCha20-Poly1305)
- Dual independent HKDF expansions (key + associated-data binding)
- Short SHA3-HMAC header integrity tag verified before any decryption
- Opaque transport marker
- Failure path does not leak structural detail
- Pre-mix of plaintext under a derived sub-key before AEAD
  (raises cost of partial-key or side-channel structural analysis)
"""

from __future__ import annotations

import os
import base64
import hmac
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class Ahx1:
    MARK = "ahx1:"

    def __init__(self, root: Optional[bytes] = None):
        if root is None:
            # Production: never leave this path. Pull from TPM / enclave.
            self._root = os.urandom(32)
        else:
            if len(root) != 32:
                raise ValueError("root must be exactly 32 bytes")
            self._root = root

        # Static context binder (not secret, just domain separation)
        self._ctx = hashlib.sha3_256(b"ahx1-v1-context").digest()[:16]

    def _hkdf(self, salt: bytes, info: bytes, length: int = 32) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(self._root)

    def _header_tag(self, header: bytes) -> bytes:
        return hmac.new(self._root, header, hashlib.sha3_256).digest()[:8]

    def _premix(self, data: bytes, mix_key: bytes) -> bytes:
        """
        Lightweight stream mix before AEAD.
        Uses a simple repeating XOR of a derived 32-byte key expanded
        by SHA3. Not a replacement for AEAD — only increases structural cost.
        """
        stream = b""
        counter = 0
        while len(stream) < len(data):
            block = hashlib.sha3_256(mix_key + counter.to_bytes(4, "big")).digest()
            stream += block
            counter += 1
        return bytes(a ^ b for a, b in zip(data, stream[: len(data)]))

    def seal(self, plain: str) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        key     = self._hkdf(salt, b"ahx1-seal-key")
        ad_key  = self._hkdf(salt, b"ahx1-ad-bind")
        mix_key = self._hkdf(salt, b"ahx1-premix")

        ad = ad_key + self._ctx
        raw = plain.encode("utf-8")
        mixed = self._premix(raw, mix_key)

        cipher = ChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, mixed, associated_data=ad)

        header = salt + nonce
        tag = self._header_tag(header)
        payload = header + tag + ct

        packed = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return self.MARK + packed

    def open(self, token: str) -> str:
        if not isinstance(token, str) or not token.startswith(self.MARK):
            raise ValueError("malformed")

        raw_b64 = token[len(self.MARK):]
        pad = 4 - (len(raw_b64) % 4)
        if pad != 4:
            raw_b64 += "=" * pad

        try:
            payload = base64.urlsafe_b64decode(raw_b64)
        except Exception:
            raise ValueError("corrupt")

        if len(payload) < 16 + 12 + 8 + 16:
            raise ValueError("truncated")

        salt  = payload[:16]
        nonce = payload[16:28]
        tag   = payload[28:36]
        ct    = payload[36:]

        if not hmac.compare_digest(tag, self._header_tag(salt + nonce)):
            raise ValueError("integrity")

        key     = self._hkdf(salt, b"ahx1-seal-key")
        ad_key  = self._hkdf(salt, b"ahx1-ad-bind")
        mix_key = self._hkdf(salt, b"ahx1-premix")
        ad = ad_key + self._ctx

        cipher = ChaCha20Poly1305(key)
        try:
            mixed = cipher.decrypt(nonce, ct, associated_data=ad)
        except Exception:
            raise ValueError("open failed")

        plain_bytes = self._premix(mixed, mix_key)  # XOR is involution
        return plain_bytes.decode("utf-8")


# ------------------------------------------------------------------
# Deterministic demo root (NEVER use in production)
# ------------------------------------------------------------------
DEMO_ROOT = bytes.fromhex(
    "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
)


if __name__ == "__main__":
    eng = Ahx1(root=DEMO_ROOT)
    msg = "Oh well 1+1=? Oh well done"
    sealed = eng.seal(msg)
    print("SEALED")
    print(sealed)
    print()
    print("OPENED")
    print(eng.open(sealed))
