"""Password hashing and JWT helpers built on the Python standard library.

No third-party dependencies: everything here (scrypt hashing, HMAC signing,
base64url encoding) is written out so the mechanism is visible.
"""

import base64
import hashlib
import hmac
import json
import os
import time

# scrypt cost parameters. Higher N means more memory and time per hash, which
# makes brute-forcing a stolen hash far more expensive.
SCRYPT_N = 2 ** 14  # 2^14 = 16384 iterations, ~16 MB of memory per hash
SCRYPT_R = 8        # scrypt block size (standard default)
SCRYPT_P = 1        # parallelism factor (standard default)

# Secret used to sign tokens. Read from the JWT_SECRET environment variable;
# falls back to a dev-only default. If this leaks, anyone can forge tokens.
SECRET_KEY = os.environ.get("JWT_SECRET", "dev-secret-change-me")


def hash_password(password: str) -> str:
    """Hash a plain password for storage: "scrypt$<salt_hex>$<hash_hex>"."""
    # A fresh 16-byte random salt per user: two users with the same password
    # still get different hashes, so one crack cannot open both accounts.
    salt = os.urandom(16)

    derive = hashlib.scrypt(
        password.encode("utf-8"),            # scrypt needs bytes, not str
        salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
    )
    # Store the algorithm, the salt and the hash so verification can redo it.
    return f"scrypt${salt.hex()}${derive.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Return True if the plain password matches the stored hash string."""
    _, salt_hex, hash_hex = stored.split("$")
    derive = hashlib.scrypt(
        password.encode("utf-8"),
        salt=bytes.fromhex(salt_hex),
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
    )
    # compare_digest, not ==, so the comparison time does not leak how many
    # leading characters matched (timing attack).
    return hmac.compare_digest(derive.hex(), hash_hex)


# ---------------------------------------------------------------------------
# JWT: create and verify tokens. Format: header.payload.signature
# ---------------------------------------------------------------------------

# HS256 = HMAC + SHA-256. The signature is derived from the server secret and
# the token contents, so it cannot be reproduced without the secret.
ALGORITHM = "HS256"


def _b64(data: bytes) -> str:
    """Encode bytes to URL-safe base64 text without padding (JWT style)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(text: str) -> bytes:
    """Reverse of _b64: URL-safe base64 text back to bytes."""
    # Restore the '=' padding that _b64 stripped; base64 needs length % 4 == 0.
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def create_token(subject: str, expires_in: int = 3600) -> str:
    """Create a signed JWT. payload = {"sub": subject, "exp": <unix time>}."""
    # "sub" identifies the token owner; "exp" is when it stops being valid.
    payload = {"sub": subject, "exp": int(time.time()) + expires_in}

    header = {"alg": ALGORITHM, "typ": "JWT"}

    # dict -> JSON text -> bytes -> base64url text, for each of the two parts.
    header_b64 = _b64(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64(json.dumps(payload).encode("utf-8"))

    # The signed input is exactly "header.payload".
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    # Final token: three dot-separated parts.
    return f"{header_b64}.{payload_b64}.{_b64(signature)}"


def decode_token(token: str) -> dict | None:
    """Verify a token's signature + expiry. Return the payload, or None if invalid."""
    # One try wraps every step that can fail on bad input: a token that is not
    # three parts (ValueError from split), broken base64 (binascii.Error), or
    # broken JSON (json.JSONDecodeError). Both of the latter subclass
    # ValueError, so a single except clause catches all of them.
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")

        # Recompute the expected signature from the received header + payload.
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected = hmac.new(
            SECRET_KEY.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()

        # Reject if the sent signature does not match the expected one.
        if not hmac.compare_digest(expected, _b64_decode(signature_b64)):
            return None

        # Signature is valid: decode the payload back into a dict.
        payload = json.loads(_b64_decode(payload_b64))
    except ValueError:
        return None

    # Reject expired tokens.
    if payload.get("exp", 0) < time.time():
        return None

    return payload
