"""
password_generator.py  –  SecureVault Pro Password Generator
=============================================================
Provides a single public function:

    generate_password(length=16, **options) -> str

Design goals
------------
* Cryptographically secure  : uses secrets module exclusively (CSPRNG).
* Guaranteed character mix  : at least one character from every enabled class
  is always present, regardless of length, so the result always satisfies
  common site rules.
* No adjacent repeats       : consecutive identical characters are avoided.
* Uniform distribution      : after mandatory characters are placed, remaining
  slots are filled with uniform random draws from the full allowed alphabet –
  no bias toward any class.
* Configurable              : every character class can be toggled; a custom
  extra-symbols string can be supplied.
"""

import secrets
import string
from typing import Optional


# ── Default character classes ────────────────────────────────────────────────
_UPPERCASE = string.ascii_uppercase               # A-Z
_LOWERCASE = string.ascii_lowercase               # a-z
_DIGITS    = string.digits                         # 0-9
_SYMBOLS   = "!@#$%^&*()_+-=[]{}|;:,.<>?"        # common special chars
                                                   # (excludes quotes / backtick
                                                   #  to avoid shell/DB issues)


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    extra_symbols: Optional[str] = None,
    exclude_chars: Optional[str] = None,
    min_uppercase: int = 1,
    min_lowercase: int = 1,
    min_digits: int = 1,
    min_symbols: int = 1,
) -> str:
    """
    Generate a cryptographically secure random password.

    Parameters
    ----------
    length : int
        Total password length (minimum 4, capped at 256).
    use_uppercase : bool
        Include uppercase letters A-Z.
    use_lowercase : bool
        Include lowercase letters a-z.
    use_digits : bool
        Include digits 0-9.
    use_symbols : bool
        Include punctuation / special characters.
    extra_symbols : str | None
        Additional characters to include in the symbol pool.
    exclude_chars : str | None
        Characters to remove from every pool (e.g. "O0Il1" for readability).
    min_uppercase / min_lowercase / min_digits / min_symbols : int
        Minimum occurrences of each class (only enforced when the class is
        enabled). Clamped to 0 if the class is disabled.

    Returns
    -------
    str
        A random password of exactly *length* characters.

    Raises
    ------
    ValueError
        If no character class is enabled, or length is too short to satisfy
        the minimum-count requirements.
    """
    # ── Validate / clamp length ───────────────────────────────────────────────
    length = max(4, min(int(length), 256))

    # ── Build per-class pools ─────────────────────────────────────────────────
    exclude = set(exclude_chars or "")

    def _pool(chars: str) -> str:
        return "".join(c for c in chars if c not in exclude)

    pool_upper   = _pool(_UPPERCASE) if use_uppercase else ""
    pool_lower   = _pool(_LOWERCASE) if use_lowercase else ""
    pool_digits  = _pool(_DIGITS)    if use_digits    else ""
    pool_symbols = _pool(_SYMBOLS)   if use_symbols   else ""

    if extra_symbols:
        pool_symbols += _pool(extra_symbols)
        pool_symbols  = "".join(dict.fromkeys(pool_symbols))  # deduplicate

    # ── Enforce minimum counts (only for enabled, non-empty pools) ────────────
    required: list[str] = []

    def _add_required(pool: str, minimum: int, enabled: bool) -> None:
        if not enabled or not pool:
            return
        for _ in range(max(0, minimum)):
            required.append(secrets.choice(pool))

    _add_required(pool_upper,  min_uppercase, use_uppercase)
    _add_required(pool_lower,  min_lowercase, use_lowercase)
    _add_required(pool_digits, min_digits,    use_digits)
    _add_required(pool_symbols, min_symbols,  use_symbols)

    # ── Full alphabet ─────────────────────────────────────────────────────────
    alphabet = pool_upper + pool_lower + pool_digits + pool_symbols
    if not alphabet:
        raise ValueError(
            "No character classes are enabled. "
            "Enable at least one of: uppercase, lowercase, digits, symbols."
        )

    if len(required) > length:
        raise ValueError(
            f"Minimum character requirements ({len(required)}) exceed "
            f"requested length ({length}). Increase length or lower minimums."
        )

    # ── Fill remaining slots ──────────────────────────────────────────────────
    remaining = length - len(required)
    filler    = [secrets.choice(alphabet) for _ in range(remaining)]

    # ── Combine and shuffle (Fisher-Yates via secrets) ────────────────────────
    password_chars = required + filler
    _secure_shuffle(password_chars)

    # ── No-adjacent-repeat pass (best-effort, non-blocking) ──────────────────
    password_chars = _break_adjacent_repeats(password_chars, alphabet)

    return "".join(password_chars)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _secure_shuffle(lst: list) -> None:
    """In-place Fisher-Yates shuffle using the CSPRNG."""
    n = len(lst)
    for i in range(n - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        lst[i], lst[j] = lst[j], lst[i]


def _break_adjacent_repeats(chars: list, alphabet: str, max_passes: int = 10) -> list:
    """
    Attempt to eliminate adjacent duplicate characters by swapping with a
    random non-adjacent position.  Gives up after *max_passes* to stay O(n).
    This is best-effort: for very short alphabets it may not fully succeed,
    which is acceptable.
    """
    n = len(chars)
    if n < 2 or len(set(alphabet)) < 2:
        return chars

    for _ in range(max_passes):
        changed = False
        for i in range(n - 1):
            if chars[i] == chars[i + 1]:
                # Find a swap candidate that doesn't create a new repeat
                candidates = [
                    j for j in range(n)
                    if j != i
                    and j != i + 1
                    and chars[j] != chars[i]
                    and (j == 0       or chars[j - 1] != chars[i + 1])
                    and (j == n - 1   or chars[j + 1] != chars[i + 1])
                ]
                if candidates:
                    j = secrets.choice(candidates)
                    chars[i + 1], chars[j] = chars[j], chars[i + 1]
                    changed = True
        if not changed:
            break

    return chars


# ── Convenience presets ───────────────────────────────────────────────────────

def generate_memorable_password(words: int = 4, separator: str = "-") -> str:
    """
    Generate a passphrase from the same wordlist used for recovery keys.
    Useful when the user wants something memorable rather than random chars.

        generate_memorable_password(4) -> "foxtrot-apple-sierra-delta"
    """
    wordlist = [
        "alpha","bravo","charlie","delta","echo","foxtrot",
        "golf","hotel","india","juliet","kilo","lima",
        "mike","november","oscar","papa","quebec","romeo",
        "sierra","tango","uniform","victor","whiskey","xray",
        "yankee","zulu","apple","banana","cherry","dragon",
        "falcon","glacier","harbor","indigo","jasper","kodiak",
        "lantern","marble","nebula","onyx","prism","quartz",
        "raven","sapphire","titan","umbra","vortex","willow",
        "xenon","yellow","zephyr",
    ]
    chosen = [secrets.choice(wordlist) for _ in range(max(2, words))]
    # Append a random 2-digit number for entropy
    chosen.append(str(secrets.randbelow(90) + 10))
    return separator.join(chosen)


def generate_pin(length: int = 6) -> str:
    """Generate a numeric PIN of *length* digits (4–12)."""
    length = max(4, min(int(length), 12))
    return "".join(str(secrets.randbelow(10)) for _ in range(length))