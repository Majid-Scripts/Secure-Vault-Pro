"""
encrypt.py  –  SecureVault Pro Encryption Module
=================================================
Provides all cryptographic operations required by gui.py:

    encrypt_message(plaintext)          -> ciphertext_b64_str
    decrypt_message(ciphertext_b64_str) -> plaintext
    hash_master_password(password)      -> stored_hash_str
    verify_master_password(password, stored_hash_str) -> bool
    set_session_password(password)      -> None
    clear_session_password()            -> None
    rotate_vault_salt()                 -> None

Cryptographic design
--------------------
* Master password  : Argon2id (via argon2-cffi) with fallback to PBKDF2-HMAC-SHA256
* Vault encryption : AES-256-GCM  (authenticated, nonce prepended to ciphertext)
* Key derivation   : HKDF-SHA256 stretches the session password + per-vault salt
                     into a 32-byte AES key every time a message is encrypted or
                     decrypted, so the raw password never sits next to the data.
* Session password : stored only in a module-level variable; wiped on lock/logout
                     via clear_session_password().
* Vault salt       : 32 random bytes stored in  data/vault.salt
                     Replaced (rotate_vault_salt) on every master-password change,
                     which forces re-encryption of all entries with a fresh key.

Dependencies
------------
    pip install cryptography argon2-cffi
"""

import os
import sys
import base64
import hashlib
import hmac
import secrets

# ── optional Argon2 (preferred); falls back to PBKDF2 if not installed ──────

# Placeholders – defined BEFORE the try block so the IDE knows every name
# is always bound, whether or not argon2-cffi is installed.
_ARGON2_AVAILABLE    = False
_ph                  = None
_VerifyMismatchError = Exception
_VerificationError   = Exception
_InvalidHashError    = Exception

try:
    from argon2 import PasswordHasher as _Argon2PH
    from argon2.exceptions import (
        VerifyMismatchError as _VerifyMismatchError,  # wrong password
        VerificationError   as _VerificationError,    # generic verify failure
        InvalidHashError    as _InvalidHashError,     # corrupt / garbage hash
    )
    _ph = _Argon2PH(
        time_cost=3,        # iterations
        memory_cost=65536,  # 64 MiB
        parallelism=2,
        hash_len=32,
        salt_len=16,
    )
    _ARGON2_AVAILABLE = True
except ImportError:
    pass  # PBKDF2 fallback will be used; placeholders above stay in effect

# ── cryptography (required) ──────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.backends import default_backend as _backend
except ImportError as e:
    raise ImportError(
        "The 'cryptography' package is required.\n"
        "Install it with:  pip install cryptography"
    ) from e


# ============================================================
#  Internal paths
# ============================================================
def _get_data_dir() -> str:
    """Mirror the same DATA_DIR logic used in gui.py."""
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    data = os.path.join(base, "data")
    os.makedirs(data, exist_ok=True)
    return data


_DATA_DIR   = _get_data_dir()
_SALT_FILE  = os.path.join(_DATA_DIR, "vault.salt")

# ============================================================
#  Session password  (in-memory only)
# ============================================================
_session_password: str | None = None


def set_session_password(password: str) -> None:
    """Store the master password in memory for the current session."""
    global _session_password
    _session_password = password


def clear_session_password() -> None:
    """Wipe the session password from memory (called on lock / logout)."""
    global _session_password
    _session_password = None


def _require_session() -> str:
    """Return the session password or raise if the vault is locked."""
    if _session_password is None:
        raise RuntimeError(
            "Vault is locked. Call set_session_password() after login."
        )
    return _session_password


# ============================================================
#  Vault salt  (per-installation, rotated on password change)
# ============================================================
def _load_vault_salt() -> bytes:
    """Load or create the 32-byte vault salt."""
    if os.path.exists(_SALT_FILE):
        with open(_SALT_FILE, "rb") as f:
            salt = f.read()
        if len(salt) == 32:
            return salt
    # First run or corrupt file – generate a fresh salt
    return _new_vault_salt()


def _new_vault_salt() -> bytes:
    """Generate and persist a fresh vault salt."""
    salt = secrets.token_bytes(32)
    with open(_SALT_FILE, "wb") as f:
        f.write(salt)
    try:
        os.chmod(_SALT_FILE, 0o600)
    except Exception:
        pass
    return salt


def rotate_vault_salt() -> None:
    """
    Replace the vault salt with a fresh one.

    Called by gui.py *before* re-encrypting vault entries with the new
    master password, so old ciphertexts (encrypted with the old key) cannot
    be decrypted with the new key even if the old password is known.
    """
    _new_vault_salt()


# ============================================================
#  AES-256-GCM key derivation
# ============================================================
def _derive_key(password: str, vault_salt: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 key from the session password and vault salt
    using HKDF-SHA256.

    Using HKDF on top of the raw password (which is already hashed/stretched
    during login) gives forward-separation between the authentication hash
    stored on disk and the encryption key used in memory.
    """
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=vault_salt,
        info=b"securevault-pro-aes256gcm-v1",
        backend=_backend(),
    )
    return hkdf.derive(password.encode("utf-8"))


# ============================================================
#  encrypt_message / decrypt_message
# ============================================================
def encrypt_message(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a base-64 string:  base64( nonce[12] + ciphertext + tag[16] )

    The nonce is randomly generated per call (GCM requirement).
    The GCM authentication tag (16 bytes) is appended automatically by the
    cryptography library and verified on decryption.
    """
    password   = _require_session()
    vault_salt = _load_vault_salt()
    key        = _derive_key(password, vault_salt)

    nonce      = secrets.token_bytes(12)           # 96-bit GCM nonce
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # ciphertext already includes the 16-byte GCM tag at the end

    blob = nonce + ciphertext                      # 12 + len(pt) + 16 bytes
    return base64.b64encode(blob).decode("ascii")


def decrypt_message(ciphertext_b64: str) -> str:
    """
    Decrypt a base-64 AES-256-GCM blob produced by encrypt_message().

    Raises ValueError on authentication failure (tampered/corrupt data).
    Raises RuntimeError if the vault is locked.
    """
    password   = _require_session()
    vault_salt = _load_vault_salt()
    key        = _derive_key(password, vault_salt)

    try:
        blob       = base64.b64decode(ciphertext_b64)
    except Exception as e:
        raise ValueError(f"Ciphertext is not valid base-64: {e}") from e

    if len(blob) < 12 + 16:
        raise ValueError("Ciphertext too short to be a valid AES-GCM blob.")

    nonce      = blob[:12]
    ciphertext = blob[12:]

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(
            "Decryption failed — wrong key or corrupted data."
        ) from e

    return plaintext_bytes.decode("utf-8")


# ============================================================
#  Master-password hashing  (for login verification only)
# ============================================================
def hash_master_password(password: str) -> str:
    """
    Hash the master password for persistent storage in master.key.

    Uses Argon2id when available; falls back to PBKDF2-HMAC-SHA256 (600 000
    iterations) so the app works without argon2-cffi installed.

    The returned string is self-describing (contains algorithm tag + params +
    salt + hash) so verify_master_password() can check it regardless of which
    algorithm produced it.
    """
    if _ARGON2_AVAILABLE:
        # argon2-cffi encodes everything (params, salt, hash) into one string
        return _ph.hash(password)

    # ── PBKDF2 fallback ──────────────────────────────────────────────────────
    salt       = secrets.token_bytes(32)
    iterations = 600_000
    dk         = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    # Format: "pbkdf2$<iterations>$<salt_hex>$<hash_hex>"
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


def verify_master_password(password: str, stored_hash: str) -> bool:
    """
    Verify *password* against a hash previously produced by hash_master_password().

    Returns True on match, False otherwise (never raises on bad input).
    """
    if not stored_hash:
        return False

    try:
        # ── Argon2 hash (starts with "$argon2") ──────────────────────────────
        if stored_hash.startswith("$argon2"):
            if not _ARGON2_AVAILABLE:
                # Can't verify Argon2 without the library – deny access safely
                return False
            try:
                # ph.verify() returns True on success, raises on any failure
                return _ph.verify(stored_hash, password)
            except _VerifyMismatchError:
                # Password is simply wrong
                return False
            except _InvalidHashError:
                # Stored hash string is corrupt / not a valid Argon2 hash
                return False
            except _VerificationError:
                # Generic Argon2 verification failure
                return False
            except Exception:
                # Catch-all: never crash the login screen
                return False

        # ── PBKDF2 fallback hash ─────────────────────────────────────────────
        if stored_hash.startswith("pbkdf2$"):
            parts = stored_hash.split("$")
            if len(parts) != 4:
                return False
            _, iterations_str, salt_hex, hash_hex = parts
            iterations    = int(iterations_str)
            salt          = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)
            test_hash     = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt, iterations
            )
            return hmac.compare_digest(test_hash, expected_hash)

        # ── Legacy plain-SHA256 (very old vaults, upgrade path) ─────────────
        # If someone ran an older version that stored a plain sha256 hex digest,
        # we still let them in so they can immediately change their password.
        if len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash):
            legacy = hashlib.sha256(password.encode()).hexdigest()
            return hmac.compare_digest(legacy, stored_hash)

    except Exception:
        pass

    return False