import hashlib
import hmac
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# HMAC-SHA256
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


# AES-128-CBC (basic shared-key transport encryption)

#   - One 16-byte AES key, hardcoded identically on every

# Wire format for every encrypted message body:
#   {"iv": "<32 hex chars>", "data": "<hex ciphertext>"}


AES_KEY_HEX = "3fae1baf5e3d4c2c9be2f1a6c88f3ac0"
AES_KEY = bytes.fromhex(AES_KEY_HEX)

# ADMIN KEY (stolen-card reporting)
ADMIN_KEY = "amrita26"


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
