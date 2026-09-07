from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO

from database import (
    get_connection,
    init_database
)

from security import verify_hmac

from ghost_engine import check_impossible_travel

import secrets
import time

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

init_database()

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/challenge")
def challenge():

    data = request.get_json()

    device_id = data.get("device_id")

    conn = get_connection()

    device = conn.execute("""
        SELECT *
        FROM devices
        WHERE device_id=?
        AND status='ACTIVE'
    """, (device_id,)).fetchone()

    if not device:
        conn.close()

        return jsonify({
            "ok": False,
            "reason": "UNKNOWN_DEVICE"
        }), 403

    nonce = secrets.token_hex(32)

    conn.execute("""
        INSERT INTO challenges
        (nonce, device_id, created_at, used)
        VALUES (?, ?, ?, 0)
    """, (
        nonce,
        device_id,
        int(time.time())
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "nonce": nonce
    })

@app.post("/api/authenticate")
def authenticate():

    data = request.get_json()
    device_id = data.get("device_id")
    nonce = data.get("nonce")

    response = data.get("response")

    now = int(time.time())

    conn = get_connection()

    device = conn.execute("""
        SELECT
            devices.*,
            zones.name AS zone,
            zones.latitude,
            zones.longitude
        FROM devices
        JOIN zones
        ON zones.id = devices.zone_id
        WHERE devices.device_id=?
        AND devices.status='ACTIVE'
    """, (device_id,)).fetchone()

    if not device:
       conn.close()

       return jsonify ( {
          "decision":"BLOCK",
          "risk": 100,
          "reason": "UNKNOWN_DEVICE",
       })

    challenge = conn.execute("""
        SELECT *
        FROM challenges
        WHERE nonce =?
        AND device_id=?
        """, (nonce, device_id)).fetchone()

    if not challenge:
        conn.close()

        return jsonify({
            "decision": "BLOCK",
            "risk": 100,
            "reason": "INVALID_NONCE"
        })

    if challenge['used']:
       conn.close()

       return jsonify({
          "decsion":"BLOCK",
          "risK": 100,
          "reason":"REPLAY_ATTACK"
       })

    if now-challenge['created_at'] > 30:
       conn.execute("""
            UPDATE challenges
            SET used =1
            WHERE nonce=?
        """,(nonce,))

       conn.commit()
       conn.close()

       return jsonify({"decision":"BLOCK",
                        "risk":100,
                        "reason":"EXPIRED_CHALLENGE"
         })
    
    message = f"{device_id}:{uid}:{nonce}"

    if not verify_hmac(device["device_secret"],
                       message,
                       response
    ):
       
       conn.close()

       return jsonify({
         "decision": "BLOCK",
         "risk": 100,
         "reason": "INVALID_DEVICE_SIGNATURE"  
          
       })
    conn.execute("""
        UPDATE challenges
        SET used=1
        WHERE nonce=?
    """, (nonce,))

    employee = conn.execute("""
        SELECT *
        FROM employees
        WHERE credential_uid=?
        AND status='ACTIVE'
    """, (uid,)).fetchone()

    risk = 0
    reasons = []

    if not employee:
        risk += 100
        reasons.append("UNKNOWN_CREDENTIAL")

    else:

        previous = conn.execute("""
            SELECT
                access_logs.*,
                zones.latitude,
                zones.longitude
            FROM access_logs
            JOIN zones
            ON zones.name = access_logs.zone
            WHERE employee_code=?
            AND result='ALLOW'
            ORDER BY timestamp DESC
            LIMIT 1
        """, (employee["employee_code"],)).fetchone()

        if previous:

            current_zone = {
                "latitude": device["latitude"],
                "longitude": device["longitude"]
            }

            previous_zone = {
                "latitude": previous["latitude"],
                "longitude": previous["longitude"]
            }

            travel = check_impossible_travel(
                previous_zone,
                current_zone,
                now - previous["timestamp"]
            )

            if travel["impossible"]:
                risk += 90
                reasons.append(
                    "IMPOSSIBLE_TRAVEL"
                )

    if risk >= 60:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    reason = ",".join(reasons) if reasons else "NORMAL"

    employee_code = (
        employee["employee_code"]
        if employee else None
    )

    conn.execute("""
        INSERT INTO access_logs
        (
            timestamp,
            employee_code,
            device_id,
            zone,
            result,
            risk_score,
            reason,
            nonce
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now,
        employee_code,
        device_id,
        device["zone"],
        decision,
        risk,
        reason,
        nonce
    ))

    conn.commit()
    conn.close()

    result = {
        "decision": decision,
        "risk": risk,
        "reason": reason,
        "zone": device["zone"]
    }

    socketio.emit(
        "access_event",
        result
    )

    return jsonify(result)


@app.get("/api/logs")
def logs():

    conn = get_connection()

    rows = conn.execute("""
        SELECT *
        FROM access_logs
        ORDER BY timestamp DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.get("/api/stats")
def stats():

    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM access_logs"
    ).fetchone()[0]

    allowed = conn.execute(
        "SELECT COUNT(*) FROM access_logs WHERE result='ALLOW'"
    ).fetchone()[0]

    blocked = conn.execute(
        "SELECT COUNT(*) FROM access_logs WHERE result='BLOCK'"
    ).fetchone()[0]

    alerts = conn.execute("""
        SELECT COUNT(*)
        FROM access_logs
        WHERE reason LIKE '%IMPOSSIBLE%'
        OR reason LIKE '%REPLAY%'
    """).fetchone()[0]

    conn.close()

    return jsonify({
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "alerts": alerts
    })


if __name__ == "__main__":

    context = (
        "certs/server.crt",
        "certs/server.key"
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        ssl_context=context,
        allow_unsafe_werkzeug=True
    )