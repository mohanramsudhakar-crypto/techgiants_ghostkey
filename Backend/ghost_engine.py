from math import radians, sin, cos, sqrt, atan2


def calculate_distance_km(
    lat1,
    lon1,
    lat2,
    lon2
):

    R = 6371.0

    lat1 = radians(lat1)
    lat2 = radians(lat2)

    dlat = lat2 - lat1
    dlon = radians(lon2 - lon1)

    a = (
        sin(dlat / 2) ** 2
        + cos(lat1)
        * cos(lat2)
        * sin(dlon / 2) ** 2
    )

    c = 2 * atan2(
        sqrt(a),
        sqrt(1 - a)
    )

    return R * c


def get_risk_level(score):

    if score <= 20:
        return "LOW"

    if score <= 50:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"


def calculate_risk(
    credential_valid,
    device_valid,
    replay_detected=False,
    impossible_travel=False,
    unusual_location=False,
    repeated_failures=False
):

    score = 0
    reasons = []

    if not credential_valid:

        score += 50
        reasons.append(
            "Invalid credential"
        )

    if not device_valid:

        score += 60
        reasons.append(
            "Invalid device authentication"
        )

    if replay_detected:

        score += 80
        reasons.append(
            "Replay attack detected"
        )

    if impossible_travel:

        score += 60
        reasons.append(
            "Impossible travel detected"
        )

    if unusual_location:

        score += 25
        reasons.append(
            "Unusual location"
        )

    if repeated_failures:

        score += 20
        reasons.append(
            "Repeated failed attempts"
        )

    if not reasons:

        reasons.append(
            "Authorized access"
        )

    return score, get_risk_level(score), reasons
