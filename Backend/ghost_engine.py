import math


EARTH_RADIUS_KM = 6371.0


def calculate_distance_km(lat1, lon1, lat2, lon2):

    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)

    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = (
        math.sin(dlat / 2) ** 2
        +
        math.cos(lat1)
        * math.cos(lat2)
        * math.sin(dlon / 2) ** 2
    )

    c = 2 * math.atan2(
        math.sqrt(a),
        math.sqrt(1 - a)
    )

    return EARTH_RADIUS_KM * c


def get_risk_level(score):

    if score <= 20:
        return "LOW"

    if score <= 50:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"


def calculate_risk(
    invalid_credential=False,
    invalid_device=False,
    replay=False,
    impossible_travel=False,
    unusual_location=False,
    repeated_failures=False
):

    score = 0
    reasons = []

    if invalid_credential:

        score += 50
        reasons.append(
            "Invalid or unauthorized credential"
        )

    if invalid_device:

        score += 60
        reasons.append(
            "Invalid or unauthorized device"
        )

    if replay:

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
            "Repeated authentication failures"
        )

    return {
        "score": score,
        "level": get_risk_level(score),
        "reasons": reasons
    }
