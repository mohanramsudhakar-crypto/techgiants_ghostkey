from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from datetime import datetime, timedelta, timezone
from database import init_database,get_connection,log_access
from security import verify_hmac
from risk_engine import calculate_Risk, calculate_distance_km
import secrets


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config["SECRET_KEY"] = "ghost-key-demo-secret"

init_database()

@app.route("/health")
def health():

    return jsonify({
        "status": "online",
        "system": "Ghost Key"
    })

@app.route(
    "/api/challenge",
    methods=["POST"]
)
def create_challenge():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "Invalid JSON"
        }), 400


    device_id = data.get(
        "device_id"
    )


    connection = get_connection()


    device = connection.execute("""
        SELECT *
        FROM devices
        WHERE device_id = ?
    """, (
        device_id,
    )).fetchone()


    connection.close()


    if not device:

        return jsonify({
            "error": "Unknown device"
        }), 403


    if not device["authorized"]:

        return jsonify({
            "error": "Device unauthorized"
        }), 403


    nonce = secrets.token_hex(32)


    now = datetime.now(
        timezone.utc
    )


    expires = (
        now
        +
        timedelta(seconds=30)
    )


    connection = get_connection()


    connection.execute("""
        INSERT INTO challenges (

            nonce,
            device_id,
            created_at,
            expires_at,
            used

        )

        VALUES (?, ?, ?, ?, 0)
    """, (

        nonce,

        device_id,

        now.isoformat(),

        expires.isoformat()

    ))


    connection.commit()

    connection.close()


    return jsonify({

        "nonce": nonce,

        "expires_in": 30

    })


# ============================================================
# ACCESS
# ============================================================

@app.route(
    "/api/access",
    methods=["POST"]
)
def access_request():

    data = request.get_json()


    if not data:

        return jsonify({

            "decision": "BLOCK",

            "reason": "Invalid request"

        }), 400


    device_id = data.get(
        "device_id"
    )

    credential_id = data.get(
        "credential_id"
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


    connection = get_connection()


    device = connection.execute("""
        SELECT *
        FROM devices
        WHERE device_id = ?
    """, (
        device_id,
    )).fetchone()


    credential = connection.execute("""
        SELECT *
        FROM credentials
        WHERE credential_id = ?
    """, (
        credential_id,
    )).fetchone()


    challenge = connection.execute("""
        SELECT *
        FROM challenges
        WHERE nonce = ?
    """, (
        nonce,
    )).fetchone()


    connection.close()


    # ========================================================
    # DEVICE VALIDATION
    # ========================================================

    if not device:

        return jsonify({

            "decision": "BLOCK",

            "risk_score": 60,

            "risk_level": "HIGH",

            "reason": "Unknown device"

        }), 403


    # ========================================================
    # CHALLENGE VALIDATION
    # ========================================================

    if not challenge:

        return jsonify({

            "decision": "BLOCK",

            "risk_score": 80,

            "risk_level": "HIGH",

            "reason": "Invalid challenge"

        }), 403


    # ========================================================
    # REPLAY
    # ========================================================

    if challenge["used"]:

        log_access(

            credential_id,

            credential["user_name"]
            if credential
            else "Unknown",

            device_id,

            device["location_name"],

            "BLOCK",

            80,

            "HIGH",

            "Replay attack detected",

            "FAILED"

        )


        return jsonify({

            "decision": "BLOCK",

            "risk_score": 80,

            "risk_level": "HIGH",

            "reason":
                "Replay attack detected"

        }), 403


    # ========================================================
    # EXPIRATION
    # ========================================================

    expires = datetime.fromisoformat(
        challenge["expires_at"]
    )


    if (
        datetime.now(timezone.utc)
        >
        expires
    ):

        return jsonify({

            "decision": "BLOCK",

            "risk_score": 80,

            "risk_level": "HIGH",

            "reason":
                "Challenge expired"

        }), 403


    # ========================================================
    # MARK NONCE USED
    # ========================================================

    connection = get_connection()


    connection.execute("""
        UPDATE challenges
        SET used = 1
        WHERE nonce = ?
    """, (
        nonce,
    ))


    connection.commit()

    connection.close()


    # ========================================================
    # DEVICE HMAC
    # ========================================================

    device_message = (
        nonce
        +
        "|"
        +
        device_id
    )


    device_valid = verify_hmac(

        device["device_secret"],

        device_message,

        device_hmac

    )


    # ========================================================
    # CARD HMAC
    # ========================================================

    credential_valid = False


    if credential:

        credential_message = (

            nonce
            +
            "|"
            +
            credential_id

        )


        credential_valid = verify_hmac(

            credential["credential_secret"],

            credential_message,

            credential_hmac

        )


    # ========================================================
    # IMPOSSIBLE TRAVEL
    # ========================================================

    impossible_travel = False


    if credential:

        connection = get_connection()


        previous = connection.execute("""
            SELECT *
            FROM access_logs

            WHERE credential_id = ?

            AND decision = 'ALLOW'

            ORDER BY id DESC

            LIMIT 1
        """, (
            credential_id,
        )).fetchone()


        connection.close()


        if previous:

            connection = get_connection()


            previous_device = connection.execute("""
                SELECT *
                FROM devices
                WHERE device_id = ?
            """, (
                previous["device_id"],
            )).fetchone()


            connection.close()


            if previous_device:

                distance = calculate_distance_km(

                    previous_device["latitude"],

                    previous_device["longitude"],

                    device["latitude"],

                    device["longitude"]

                )


                previous_time = datetime.fromisoformat(

                    previous["timestamp"]

                )


                current_time = datetime.now(
                    timezone.utc
                )


                seconds = (

                    current_time
                    -
                    previous_time

                ).total_seconds()


                if seconds > 0:

                    speed = (

                        distance
                        /
                        (seconds / 3600)

                    )


                    # Demonstration threshold

                    if speed > 900:

                        impossible_travel = True


    # ========================================================
    # RISK
    # ========================================================

    score, risk_level, reasons = calculate_risk(

        credential_valid,

        device_valid,

        impossible_travel=
            impossible_travel

    )


    # ========================================================
    # AUTHORIZATION
    # ========================================================

    authorized = (

        credential is not None

        and

        credential["authorized"]

    )


    if not authorized:

        score += 20

        risk_level = "HIGH"

        reasons.append(
            "Credential unauthorized"
        )


    # ========================================================
    # FINAL DECISION
    # ========================================================

    if (

        device_valid

        and

        credential_valid

        and

        authorized

        and

        score <= 50

    ):

        decision = "ALLOW"

        authentication_result = "SUCCESS"


    else:

        decision = "BLOCK"

        authentication_result = "FAILED"


    reason = "; ".join(
        reasons
    )


    user_name = (

        credential["user_name"]

        if credential

        else "Unknown"

    )


    # ========================================================
    # DATABASE LOG
    # ========================================================

    log_access(

        credential_id,

        user_name,

        device_id,

        device["location_name"],

        decision,

        score,

        risk_level,

        reason,

        authentication_result

    )


    # ========================================================
    # DASHBOARD EVENT
    # ========================================================

    event = {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "credential_id":
            credential_id,

        "user_name":
            user_name,

        "device_id":
            device_id,

        "location":
            device["location_name"],

        "decision":
            decision,

        "risk_score":
            score,

        "risk_level":
            risk_level,

        "reason":
            reason

    }


    socketio.emit(
        "access_event",
        event
    )


    return jsonify(event)


# ============================================================
# LOGS
# ============================================================

@app.route(
    "/api/logs",
    methods=["GET"]
)
def get_logs():

    connection = get_connection()


    logs = connection.execute("""
        SELECT *
        FROM access_logs
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()


    connection.close()


    return jsonify([

        dict(row)

        for row in logs

    ])


# ============================================================
# STATISTICS
# ============================================================

@app.route(
    "/api/stats",
    methods=["GET"]
)
def get_stats():

    connection = get_connection()


    total = connection.execute("""
        SELECT COUNT(*) AS count
        FROM access_logs
    """).fetchone()["count"]


    allowed = connection.execute("""
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE decision = 'ALLOW'
    """).fetchone()["count"]


    blocked = connection.execute("""
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE decision = 'BLOCK'
    """).fetchone()["count"]


    critical = connection.execute("""
        SELECT COUNT(*) AS count
        FROM access_logs
        WHERE risk_level = 'CRITICAL'
    """).fetchone()["count"]


    connection.close()


    return jsonify({

        "total": total,

        "allowed": allowed,

        "blocked": blocked,

        "critical": critical

    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    print()
    print("==============================")
    print("       GHOST KEY SERVER")
    print("==============================")
    print()
    print(
        "Server: http://0.0.0.0:5000"
    )
    print()


    socketio.run(

        app,

        host="0.0.0.0",

        port=5000,

        debug=True

    )
