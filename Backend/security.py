import hashlib
import hmac


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
