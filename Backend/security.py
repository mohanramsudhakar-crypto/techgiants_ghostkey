import hashlib
import hmac


def hmac_sha256(secret, message):
    return hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(secret, message, received_hmac):
    
    expected = hmac_sha256(
        secret,
        message
    )

    return hmac.compare_digest(
        expected,
        received_hmac
    )

