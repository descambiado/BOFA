"""Password hashing helpers with legacy SHA-256 migration support."""

import hashlib
import hmac
import os
import secrets

PASSWORD_SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000


def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or int(os.getenv("BOFA_PASSWORD_ITERATIONS", str(DEFAULT_ITERATIONS)))
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PASSWORD_SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    if encoded.startswith(f"{PASSWORD_SCHEME}$"):
        try:
            _, raw_iterations, raw_salt, expected = encoded.split("$", 3)
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(raw_salt),
                int(raw_iterations),
            )
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(digest.hex(), expected)

    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, encoded)


def needs_rehash(encoded: str) -> bool:
    if not encoded.startswith(f"{PASSWORD_SCHEME}$"):
        return True
    try:
        iterations = int(encoded.split("$", 2)[1])
    except (IndexError, ValueError):
        return True
    return iterations < int(os.getenv("BOFA_PASSWORD_ITERATIONS", str(DEFAULT_ITERATIONS)))
