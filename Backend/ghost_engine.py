import math

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000

    p1 = math.radians(lat1)
    p2 = math.radians(lat2)

    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2-lon1)

    a = (
        math.sin(dp / 2) ** 2
        +
        math.cos(p1)
        * math.cos(p2)
        * math.sin(dl / 2) ** 2
    )

    return 2 * R * math.atan2(
        math.sqrt(a),
        math.sqrt(1 - a)
    )


def minimum_travel_seconds(distance):
    return max(5, distance/5)


def check_impossible_travel(previous_zone, current_zone, elapsed_seconds):
    distance = haversine(
        previous_zone["latitude"],
        previous_zone["longitude"],
        current_zone["latitude"],
        current_zone["longitude"]
    )

    minimum_time = minimum_travel_seconds(distance)

    impossible = (distance>50 and elapsed_seconds< minimum_time)

    return {
        "distance": distance,
        "minimum_time": minimum_time,
        "impossible": impossible
    }