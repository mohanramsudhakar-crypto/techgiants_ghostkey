import hashlib
import hmac
import os

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


# ============================================================
# HMAC-SHA256
# ============================================================
# Unchanged - still used to authenticate devices/credentials
# against a challenge nonce. AES (below) is a separate layer
# that encrypts the *transport* so the HMACs, card IDs, and
# decisions aren't sitting in plaintext on the wire.
# ============================================================

def hmac_sha256(secret, message):
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(secret, message, received_hmac):
    if not received_hmac:
        return False

    expected = hmac_sha256(secret, message)

    return hmac.compare_digest(
        expected,
        received_hmac
    )


# ============================================================
# AES-128-CBC (basic shared-key transport encryption)
# ============================================================
# This is intentionally the *simplest* useful scheme, not a
# production-grade one:
#
#   - One 16-byte AES key, hardcoded identically on every
#     ESP32 node, in this backend, and in app.js (dashboard).
#   - No key exchange / no rotation. Anyone with the source
#     code has the key.
#   - A fresh random IV is generated for every single message
#     (never reused), which is the one non-negotiable rule for
#     CBC mode.
#
# What it DOES buy you: anyone sniffing the WiFi/LAN traffic
# between the readers, the server, and the dashboard sees only
# ciphertext instead of card IDs, HMACs, and access decisions
# in plaintext. For a real deployment you'd want TLS (HTTPS)
# and a proper key-exchange/rotation scheme instead of a
# hardcoded shared key.
#
# Wire format for every encrypted message body:
#   {"iv": "<32 hex chars>", "data": "<hex ciphertext>"}
# ============================================================

# Same 16 bytes must be hardcoded in:
#   - ghostkey.ino       (AES_KEY[16])
#   - ghostkeynode2.ino  (AES_KEY[16])
#   - app.js             (AES_KEY_HEX)
AES_KEY_HEX = "3fae1baf5e3d4c2c9be2f1a6c88f3ac0"
AES_KEY = bytes.fromhex(AES_KEY_HEX)


# ============================================================
# ADMIN KEY (stolen-card reporting)
# ============================================================
# A basic shared secret the dashboard must send along with any
# "report stolen" / "reinstate" request. This is NOT real auth
# (no per-user login, no expiry) - it just stops a stray or
# accidental API call from disabling somebody's card. Change
# this to your own private value; it must match ADMIN_KEY in
# app.js.
# ============================================================

ADMIN_KEY = "ghostkey_admin_2026"


def aes_encrypt(plaintext):
    """
    Encrypt a UTF-8 string with AES-128-CBC + PKCS7 padding.
    Returns {"iv": hex, "data": hex}.
    """

    iv = os.urandom(16)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode("utf-8"), AES.block_size)
    )

    return {
        "iv": iv.hex(),
        "data": ciphertext.hex()
    }


def aes_decrypt(payload):
    """
    Decrypt {"iv": hex, "data": hex} back into a UTF-8 string.

    Raises ValueError/KeyError if the payload is malformed,
    the key doesn't match, or the ciphertext was tampered with
    (bad padding).
    """

    iv = bytes.fromhex(payload["iv"])
    ciphertext = bytes.fromhex(payload["data"])

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode("utf-8")
