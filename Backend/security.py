import hashlib
import hmac


def calculate_hmac(secret, message):
    return hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(secret, message, received):
    expected = calculate_hmac(secret, message)

    return hmac.compare_digest(
        expected,
        received
    )

