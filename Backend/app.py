from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timezone
import secrets
import json
import math

from database import get_connection, initialize_database
from security import (
    hmac_sha256,
    verify_hmac,
    aes_encrypt,
    aes_decrypt
)


# ============================================================
# FLASK SETUP
# ============================================================

app = Flask(__name__)

CORS(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

initialize_database()


# ============================================================
# TIME FUNCTIONS
# ============================================================

def now_utc():
    """
    Return current UTC time as timezone-aware datetime.
    """
    return datetime.now(timezone.utc)


def iso_now():
    """
    Return current UTC time as ISO formatted string.
    """
    return now_utc().isoformat()


def parse_time(value):
    """
    Convert stored time into a timezone-aware datetime.

    Supports:
    - Unix timestamps (int/float)
    - ISO datetime strings
    """

    if value is None:
        return None

    # SQLite may return Unix timestamp
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc
        )

    # ISO formatted string
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)

        # If the string has no timezone,
        # assume UTC.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    raise TypeError(
        f"Unsupported time value: {type(value)}"
    )


# ============================================================
# ENCRYPTED REQUEST / RESPONSE HELPERS
# ============================================================
# Every JSON body that crosses the wire to/from an ESP32 node
# or the dashboard is now wrapped as {"iv": ..., "data": ...}
# (see security.py for the AES-128-CBC implementation). These
# two helpers are the single choke point that does the
# wrapping/unwrapping so the route handlers below barely
# change from the plaintext version.
# ============================================================

def encrypted_response(payload_dict, status=200):
    """
    JSON-encode payload_dict, AES-encrypt it, and return it
    as a Flask response with the given status code.
    """

    plaintext = json.dumps(payload_dict)

    return jsonify(aes_encrypt(plaintext)), status


def decrypt_request_body():
    """
    Read the incoming request's {"iv":..., "data":...} JSON
    body and return the decrypted payload as a dict.

    Returns None if the body is missing/malformed or
    decryption fails (bad key, tampered ciphertext, etc).
    """

    envelope = request.get_json(silent=True)

    if not envelope:
        return None

    if "iv" not in envelope or "data" not in envelope:
        return None

    try:
        plaintext = aes_decrypt(envelope)
        return json.loads(plaintext)

    except Exception:
        return None


# ============================================================
# HAVERSINE DISTANCE
# ============================================================

def haversine_distance(
    lat1,
    lon1,
    lat2,
    lon2
):
    """
    Calculate distance between two GPS coordinates
    in kilometers.
    """

    earth_radius = 6371.0

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

    return earth_radius * c


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score <= 20:
        return "LOW"

    elif score <= 50:
        return "MEDIUM"

    elif score <= 80:
        return "HIGH"

    else:
        return "CRITICAL"


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    credential_authorized=True,
    device_authorized=True,
    replay=False,
    impossible_travel=False,
    unusual_location=False,
    repeated_failures=False
):

    score = 0
    reasons = []

    # --------------------------------------------------------
    # Unauthorized credential
    # --------------------------------------------------------

    if not credential_authorized:

        score += 50

        reasons.append(
            "Unauthorized credential"
        )

    # --------------------------------------------------------
    # Unauthorized device
    # --------------------------------------------------------

    if not device_authorized:

        score += 60

        reasons.append(
            "Unauthorized device"
        )

    # --------------------------------------------------------
    # Replay attack
    # --------------------------------------------------------

    if replay:

        score += 80

        reasons.append(
            "Replay attack detected"
        )

    # --------------------------------------------------------
    # Impossible travel
    # --------------------------------------------------------

    if impossible_travel:

        score += 60

        reasons.append(
            "Impossible travel detected"
        )

    # --------------------------------------------------------
    # Unusual location
    # --------------------------------------------------------

    if unusual_location:

        score += 25

        reasons.append(
            "Unusual location"
        )

    # --------------------------------------------------------
    # Repeated failures
    # --------------------------------------------------------

    if repeated_failures:

        score += 20

        reasons.append(
            "Repeated authentication failures"
        )

    # --------------------------------------------------------
    # Default reason
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "Normal authentication"
        )

    level = get_risk_level(score)

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }


# ============================================================
# ACCESS LOGGING
# ============================================================

def save_access_log(
    credential_id,
    user_name,
    device_id,
    location_name,
    decision,
    risk_score,
    risk_level,
    reason,
    authentication_result
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO access_logs
        (
            timestamp,
            credential_id,
            user_name,
            device_id,
            location_name,
            decision,
            risk_score,
            risk_level,
            reason,
            authentication_result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            iso_now(),
            credential_id,
            user_name,
            device_id,
            location_name,
            decision,
            risk_score,
            risk_level,
            reason,
            authentication_result
        )
    )

    conn.commit()

    conn.close()


# ============================================================
# REAL-TIME EVENT
# ============================================================
# The dashboard also gets the AES treatment: instead of
# emitting the plaintext event dict over Socket.IO, we emit
# the same {"iv":..., "data":...} envelope and app.js decrypts
# it client-side before rendering the row.
# ============================================================

def emit_access_event(data):

    socketio.emit(
        "access_event",
        aes_encrypt(json.dumps(data))
    )


# ============================================================
# HEALTH CHECK
# ============================================================
# Left as plaintext on purpose - it's a convenience endpoint
# for curl/browser checks and isn't used by the ESP32 nodes
# or the dashboard's normal flow.
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "online",
        "service": "Ghost Key Backend",
        "time": iso_now()
    })


# ============================================================
# CHALLENGE ENDPOINT
# ============================================================

@app.route(
    "/api/challenge",
    methods=["GET"]
)
def create_challenge():

    # --------------------------------------------------------
    # Generate cryptographically secure nonce
    # --------------------------------------------------------

    nonce = secrets.token_hex(16)

    created_at = now_utc()

    expires_at = (
        created_at.timestamp()
        + 30
    )

    # --------------------------------------------------------
    # Store challenge
    # --------------------------------------------------------

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO challenges
        (
            nonce,
            device_id,
            created_at,
            expires_at,
            used
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            nonce,
            "",
            created_at.timestamp(),
            expires_at,
            0
        )
    )

    conn.commit()

    conn.close()

    # --------------------------------------------------------
    # Return challenge (encrypted)
    # --------------------------------------------------------

    return encrypted_response({
        "nonce": nonce,
        "expires_in": 30
    })


# ============================================================
# ACCESS ENDPOINT
# ============================================================

@app.route(
    "/api/access",
    methods=["POST"]
)
def access():

    # ========================================================
    # READ + DECRYPT REQUEST
    # ========================================================
    # The body arriving here is now {"iv":..., "data":...}
    # produced by the ESP32's aesEncrypt(). If it can't be
    # decrypted, we have no way to know who's asking, so this
    # one error case stays plaintext - there's nothing
    # meaningful to encrypt yet since we don't have a session.
    # ========================================================

    data = decrypt_request_body()

    if not data:

        return jsonify({
            "decision": "BLOCK",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "reason": "Missing or undecryptable request body",
            "authentication_result": "FAILED"
        }), 400

    credential_id = data.get(
        "credential_id"
    )

    device_id = data.get(
        "device_id"
    )

    nonce = data.get(
        "nonce"
    )

    device_hmac = data.get(
        "device_hmac"
    )

    credential_hmac = data.get(
        "credential_hmac"
    )

    # ========================================================
    # BASIC VALIDATION
    # ========================================================

    if not credential_id:
        return jsonify({
            "decision": "BLOCK",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "reason": "Missing credential ID",
            "authentication_result": "FAILED"
        }), 400

    if not device_id:
        return jsonify({
            "decision": "BLOCK",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "reason": "Missing device ID",
            "authentication_result": "FAILED"
        }), 400

    if not nonce:
        return jsonify({
            "decision": "BLOCK",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "reason": "Missing challenge nonce",
            "authentication_result": "FAILED"
        }), 400

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    conn = get_connection()

    cursor = conn.cursor()

    # ========================================================
    # FIND CHALLENGE
    # ========================================================

    cursor.execute(
        """
        SELECT *
        FROM challenges
        WHERE nonce = ?
        """,
        (nonce,)
    )

    challenge = cursor.fetchone()

    if not challenge:

        conn.close()

        return encrypted_response({
            "decision": "BLOCK",
            "risk_score": 80,
            "risk_level": "HIGH",
            "reason": "Invalid challenge",
            "authentication_result": "FAILED"
        }, 403)

    # ========================================================
    # REPLAY DETECTION
    # ========================================================

    if challenge["used"]:

        conn.close()

        risk = calculate_risk(
            replay=True
        )

        save_access_log(
            credential_id,
            "Unknown",
            device_id,
            "Unknown",
            "BLOCK",
            risk["score"],
            risk["level"],
            "Replay attack detected",
            "REPLAY_DETECTED"
        )

        event = {
            "timestamp": iso_now(),
            "credential_id": credential_id,
            "user_name": "Unknown",
            "device_id": device_id,
            "location_name": "Unknown",
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Replay attack detected",
            "authentication_result": "REPLAY_DETECTED"
        }

        emit_access_event(event)

        return encrypted_response(event, 403)

    # ========================================================
    # CHECK EXPIRATION
    # ========================================================

    current_time = now_utc()

    expires_at = parse_time(
        challenge["expires_at"]
    )

    if current_time > expires_at:

        # Mark expired challenge as used
        cursor.execute(
            """
            UPDATE challenges
            SET used = 1
            WHERE nonce = ?
            """,
            (nonce,)
        )

        conn.commit()

        conn.close()

        risk = calculate_risk(
            replay=True
        )

        return encrypted_response({
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Challenge expired",
            "authentication_result": "EXPIRED"
        }, 403)

    # ========================================================
    # MARK CHALLENGE AS USED
    # ========================================================

    cursor.execute(
        """
        UPDATE challenges
        SET
            used = 1,
            device_id = ?
        WHERE nonce = ?
        """,
        (
            device_id,
            nonce
        )
    )

    conn.commit()

    # ========================================================
    # FIND DEVICE
    # ========================================================

    cursor.execute(
        """
        SELECT *
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,)
    )

    device = cursor.fetchone()

    # ========================================================
    # DEVICE VALIDATION
    # ========================================================

    if not device:

        conn.close()

        risk = calculate_risk(
            device_authorized=False
        )

        event = {
            "timestamp": iso_now(),
            "credential_id": credential_id,
            "user_name": "Unknown",
            "device_id": device_id,
            "location_name": "Unknown",
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Unknown device",
            "authentication_result": "INVALID_DEVICE"
        }

        save_access_log(
            credential_id,
            "Unknown",
            device_id,
            "Unknown",
            "BLOCK",
            risk["score"],
            risk["level"],
            "Unknown device",
            "INVALID_DEVICE"
        )

        emit_access_event(event)

        return encrypted_response(event, 403)

    # ========================================================
    # DEVICE AUTHORIZATION
    # ========================================================

    device_authorized = bool(
        device["authorized"]
    )

    # ========================================================
    # VERIFY DEVICE HMAC
    # ========================================================

    device_message = (
        nonce
        + "|"
        + device_id
    )

    device_valid = verify_hmac(
        device["device_secret"],
        device_message,
        device_hmac
    )

    if not device_valid:

        conn.close()

        risk = calculate_risk(
            device_authorized=device_authorized
        )

        # Increase risk for invalid HMAC
        risk["score"] += 50

        risk["level"] = get_risk_level(
            risk["score"]
        )

        risk["reasons"].append(
            "Invalid device HMAC"
        )

        event = {
            "timestamp": iso_now(),
            "credential_id": credential_id,
            "user_name": "Unknown",
            "device_id": device_id,
            "location_name": device["location_name"],
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Invalid device HMAC",
            "authentication_result": "INVALID_DEVICE_HMAC"
        }

        save_access_log(
            credential_id,
            "Unknown",
            device_id,
            device["location_name"],
            "BLOCK",
            risk["score"],
            risk["level"],
            "Invalid device HMAC",
            "INVALID_DEVICE_HMAC"
        )

        emit_access_event(event)

        return encrypted_response(event, 403)

    # ========================================================
    # FIND CREDENTIAL
    # ========================================================

    cursor.execute(
        """
        SELECT *
        FROM credentials
        WHERE credential_id = ?
        """,
        (credential_id,)
    )

    credential = cursor.fetchone()

    # ========================================================
    # UNKNOWN CREDENTIAL
    # ========================================================

    if not credential:

        conn.close()

        risk = calculate_risk(
            credential_authorized=False
        )

        event = {
            "timestamp": iso_now(),
            "credential_id": credential_id,
            "user_name": "Unknown",
            "device_id": device_id,
            "location_name": device["location_name"],
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Unknown credential",
            "authentication_result": "INVALID_CREDENTIAL"
        }

        save_access_log(
            credential_id,
            "Unknown",
            device_id,
            device["location_name"],
            "BLOCK",
            risk["score"],
            risk["level"],
            "Unknown credential",
            "INVALID_CREDENTIAL"
        )

        emit_access_event(event)

        return encrypted_response(event, 403)

    # ========================================================
    # CREDENTIAL AUTHORIZATION
    # ========================================================

    credential_authorized = bool(
        credential["authorized"]
    )

    user_name = credential["user_name"]

    # ========================================================
    # VERIFY CREDENTIAL HMAC
    # ========================================================

    credential_message = (
        nonce
        + "|"
        + credential_id
    )

    credential_valid = verify_hmac(
        credential["credential_secret"],
        credential_message,
        credential_hmac
    )

    if not credential_valid:

        conn.close()

        risk = calculate_risk(
            credential_authorized=credential_authorized
        )

        # Add invalid HMAC risk
        risk["score"] += 50

        risk["level"] = get_risk_level(
            risk["score"]
        )

        risk["reasons"].append(
            "Invalid credential HMAC"
        )

        event = {
            "timestamp": iso_now(),
            "credential_id": credential_id,
            "user_name": user_name,
            "device_id": device_id,
            "location_name": device["location_name"],
            "decision": "BLOCK",
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "reason": "Invalid credential HMAC",
            "authentication_result": "INVALID_CREDENTIAL_HMAC"
        }

        save_access_log(
            credential_id,
            user_name,
            device_id,
            device["location_name"],
            "BLOCK",
            risk["score"],
            risk["level"],
            "Invalid credential HMAC",
            "INVALID_CREDENTIAL_HMAC"
        )

        emit_access_event(event)

        return encrypted_response(event, 403)

    # ========================================================
    # IMPOSSIBLE TRAVEL DETECTION
    # ========================================================

    impossible_travel = False
    travel_reason = ""

    cursor.execute(
        """
        SELECT
            timestamp,
            device_id,
            location_name
        FROM access_logs
        WHERE
            credential_id = ?
            AND decision = 'ALLOW'
        ORDER BY id DESC
        LIMIT 1
        """,
        (credential_id,)
    )

    previous_access = cursor.fetchone()

    if previous_access:

        previous_time = parse_time(
            previous_access["timestamp"]
        )

        current_time = now_utc()

        elapsed_seconds = (
            current_time - previous_time
        ).total_seconds()

        # Prevent division by zero
        if elapsed_seconds < 1:
            elapsed_seconds = 1

        # ----------------------------------------------------
        # Find previous device
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE device_id = ?
            """,
            (previous_access["device_id"],)
        )

        previous_device = cursor.fetchone()

        if previous_device:

            # ------------------------------------------------
            # Distance between locations
            # ------------------------------------------------

            distance_km = haversine_distance(
                previous_device["latitude"],
                previous_device["longitude"],
                device["latitude"],
                device["longitude"]
            )

            # ------------------------------------------------
            # Travel speed
            # ------------------------------------------------

            elapsed_hours = (
                elapsed_seconds / 3600
            )

            required_speed = (
                distance_km / elapsed_hours
            )

            print()
            print("================================")
            print("IMPOSSIBLE TRAVEL CHECK")
            print("================================")
            print(
                "Previous Device:",
                previous_access["device_id"]
            )
            print(
                "Current Device:",
                device_id
            )
            print(
                "Distance:",
                round(distance_km, 2),
                "km"
            )
            print(
                "Elapsed:",
                round(elapsed_seconds, 2),
                "seconds"
            )
            print(
                "Required Speed:",
                round(required_speed, 2),
                "km/h"
            )
            print("================================")

            # ------------------------------------------------
            # Impossible travel threshold
            # ------------------------------------------------

            if (
                previous_access["device_id"]
                != device_id
                and required_speed > 900
            ):

                impossible_travel = True

                travel_reason = (
                    "Impossible travel detected: "
                    + str(round(required_speed, 2))
                    + " km/h required"
                )

    # ========================================================
    # REPEATED FAILURE CHECK
    # ========================================================

    cursor.execute(
        """
        SELECT COUNT(*) AS failure_count
        FROM access_logs
        WHERE
            credential_id = ?
            AND decision = 'BLOCK'
            AND timestamp >= ?
        """,
        (
            credential_id,
            (
                now_utc().timestamp()
                - 300
            )
        )
    )

    failure_row = cursor.fetchone()

    repeated_failures = False

    if failure_row:

        try:
            repeated_failures = (
                int(
                    failure_row["failure_count"]
                ) >= 3
            )
        except Exception:
            repeated_failures = False

    # ========================================================
    # CALCULATE RISK
    # ========================================================

    risk = calculate_risk(
        credential_authorized=credential_authorized,
        device_authorized=device_authorized,
        replay=False,
        impossible_travel=impossible_travel,
        unusual_location=False,
        repeated_failures=repeated_failures
    )

    # ========================================================
    # DECISION
    # ========================================================

    if not credential_authorized:

        decision = "BLOCK"

        reason = (
            "Unauthorized credential"
        )

        authentication_result = (
            "UNAUTHORIZED_CREDENTIAL"
        )

    elif not device_authorized:

        decision = "BLOCK"

        reason = (
            "Unauthorized device"
        )

        authentication_result = (
            "UNAUTHORIZED_DEVICE"
        )

    elif impossible_travel:

        decision = "BLOCK"

        reason = travel_reason

        authentication_result = (
            "IMPOSSIBLE_TRAVEL"
        )

    elif risk["score"] > 50:

        decision = "BLOCK"

        reason = "; ".join(
            risk["reasons"]
        )

        authentication_result = (
            "HIGH_RISK"
        )

    else:

        decision = "ALLOW"

        reason = (
            "Authentication successful"
        )

        authentication_result = (
            "AUTHENTICATED"
        )

    # ========================================================
    # CLOSE DATABASE
    # ========================================================

    conn.close()

    # ========================================================
    # SAVE LOG
    # ========================================================

    save_access_log(
        credential_id,
        user_name,
        device_id,
        device["location_name"],
        decision,
        risk["score"],
        risk["level"],
        reason,
        authentication_result
    )

    # ========================================================
    # EVENT DATA
    # ========================================================

    event = {
        "timestamp": iso_now(),
        "credential_id": credential_id,
        "user_name": user_name,
        "device_id": device_id,
        "location_name": device["location_name"],
        "decision": decision,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "reason": reason,
        "authentication_result": authentication_result
    }

    # ========================================================
    # REAL-TIME DASHBOARD EVENT
    # ========================================================

    emit_access_event(event)

    # ========================================================
    # CONSOLE OUTPUT
    # ========================================================

    print()
    print("==========================================")
    print("          GHOST KEY ACCESS")
    print("==========================================")
    print(
        "Credential:",
        credential_id
    )
    print(
        "User:",
        user_name
    )
    print(
        "Device:",
        device_id
    )
    print(
        "Location:",
        device["location_name"]
    )
    print(
        "Decision:",
        decision
    )
    print(
        "Risk Score:",
        risk["score"]
    )
    print(
        "Risk Level:",
        risk["level"]
    )
    print(
        "Reason:",
        reason
    )
    print(
        "Authentication:",
        authentication_result
    )
    print("==========================================")
    print()

    # ========================================================
    # RETURN RESULT (encrypted)
    # ========================================================

    if decision == "ALLOW":

        return encrypted_response(event, 200)

    else:

        return encrypted_response(event, 403)


# ============================================================
# GET ACCESS LOGS
# ============================================================

@app.route(
    "/api/logs",
    methods=["GET"]
)
def get_logs():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM access_logs
        ORDER BY id DESC
        LIMIT 100
        """
    )

    rows = cursor.fetchall()

    conn.close()

    logs = []

    for row in rows:

        logs.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "credential_id": row["credential_id"],
            "user_name": row["user_name"],
            "device_id": row["device_id"],
            "location_name": row["location_name"],
            "decision": row["decision"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "reason": row["reason"],
            "authentication_result":
                row["authentication_result"]
        })

    return encrypted_response(logs)


# ============================================================
# STATISTICS
# ============================================================

@app.route(
    "/api/stats",
    methods=["GET"]
)
def get_stats():

    conn = get_connection()

    cursor = conn.cursor()

    # --------------------------------------------------------
    # Total attempts
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM access_logs
        """
    )

    total = cursor.fetchone()["count"]

    # --------------------------------------------------------
    # Allowed
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE decision = 'ALLOW'
        """
    )

    allowed = cursor.fetchone()["count"]

    # --------------------------------------------------------
    # Blocked
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE decision = 'BLOCK'
        """
    )

    blocked = cursor.fetchone()["count"]

    # --------------------------------------------------------
    # Critical
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE risk_level = 'CRITICAL'
        """
    )

    critical = cursor.fetchone()["count"]

    # --------------------------------------------------------
    # High risk
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE risk_level = 'HIGH'
        """
    )

    high = cursor.fetchone()["count"]

    conn.close()

    return encrypted_response({
        "total_attempts": total,
        "allowed": allowed,
        "blocked": blocked,
        "critical": critical,
        "high_risk": high
    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("==============================================")
    print("          GHOST KEY BACKEND")
    print("==============================================")
    print("Server: http://0.0.0.0:5000")
    print("Health: http://127.0.0.1:5000/health")
    print("Challenge: /api/challenge")
    print("Access: /api/access")
    print("Logs: /api/logs")
    print("Stats: /api/stats")
    print("AES: all payloads above except /health are")
    print("     encrypted - see security.py AES_KEY_HEX")
    print("==============================================")
    print()

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )
