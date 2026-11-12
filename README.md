# ahx1

Zero-password AEAD transport engine.

No user passphrase. Root entropy only.  
Intended production root source: TPM 2.0, Secure Enclave, or equivalent hardware keystore.

## Design

- ChaCha20-Poly1305 (AEAD)
- Dual independent HKDF-SHA256 expansions (encryption key + associated-data binding)
- SHA3-HMAC short header integrity tag (checked before any decryption attempt)
- Lightweight pre-mix of plaintext under a third derived key before AEAD
- Opaque transport marker `ahx1:`
- Failure paths return generic errors only

The pre-mix + dual derivation + header tag raise the cost of automated structural reverse-engineering and partial-key analysis. Security still rests entirely on the secrecy of the 256-bit root.

## Install

```bash
pip install cryptography
```

Copy `ahx1.py` into your project (or install as a local module).

## Usage

```python
from ahx1 import Ahx1

# Production: root MUST come from hardware.
# Demo only:
root = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00")
eng = Ahx1(root=root)

token = eng.seal("secret message")
print(token)          # ahx1:...

plain = eng.open(token)
print(plain)          # secret message
```

## Demo seal of the original phrase

```
Oh well 1+1=? Oh well done
```

→

```
ahx1:8m9du3JWu2vuupCCQDPiVsSMRZgpAQkw8exu54uUxnLINhkYFg_Bz69DlPDn5cSqUsMQN9JCL3I55YkDhtb5ify2GKXaYovgZQII2DXe
```

## GitHub Pages

A static documentation page lives at:

https://yshiecast31-maker.github.io/ahx1/

## Security notes

- Never hard-code a production root in source.
- Never derive the root from a user password if you want the zero-password property.
- The library deliberately avoids differentiated error messages that would help an attacker map the wire format.
- This is not a full memory-hard or anti-debug runtime. Pair it with platform protections (enclave, pointer authentication, encrypted heap, etc.) when the threat model requires it.

## License

MIT
