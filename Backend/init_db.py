import secrets
from database import get_connection, init_database

init_database()

conn = get_connection()

zones = [
    ("LAB", 13.0827, 80.2707),
    ("OFFICE", 13.0850, 80.2750),
    ("SERVER ROOM", 13.0900, 80.2800),
    ("PARKING", 13.0750, 80.2650)
]

for name, lat, lon in zones:
    conn.execute("""
        INSERT OR IGNORE INTO zones(name, latitude, longitude) VALUES (?, ?, ?)""",
        (name, lat, lon)
    )

conn.execute("""
INSERT OR IGNORE INTO employees
(name, employee_code, credential_uid, credential_secret)
VALUES (?, ?, ?, ?)
""",(
    "Alex"
    "EMP001"
    "YOUR_CARD_UID",
    secrets.token_hex(32)
))

zone= conn.execute(
    "select id FROM zones WHERE name='lab'"
).fetchone()

conn.execute("""
INSERT OR IGNORE INTO devices
(device_id,zone_id,device_secret)
VALUES(?,?,?)
""",(
    "READER-LAB-01",
    zone["id"],
    secrets.token_hex(32)
))

conn.commit()
conn.close()

print("Database initialized.")