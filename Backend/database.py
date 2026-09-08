import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "ghostkey.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# MIGRATION HELPER
# ============================================================
# ghostkey.db may already exist on disk from before the
# stolen-card feature was added. CREATE TABLE IF NOT EXISTS
# won't add new columns to a table that already exists, so
# this checks for each new column and ALTERs it in if missing.
# ============================================================

def _add_column_if_missing(cursor, table, column, coltype):

    cursor.execute(f"PRAGMA table_info({table})")

    existing_columns = [row[1] for row in cursor.fetchall()]

    if column not in existing_columns:

        cursor.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"
        )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    conn = get_connection()
    cursor = conn.cursor()

    # --------------------------------------------------------
    # DEVICES
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_name TEXT NOT NULL,
            location_name TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            device_secret TEXT NOT NULL,
            authorized INTEGER DEFAULT 1
        )
    """)

    # --------------------------------------------------------
    # CREDENTIALS
    # --------------------------------------------------------
    # "status" distinguishes WHY a credential is blocked:
    #   active  - normal, working card
    #   stolen  - reported stolen, hard-blocked, dashboard alarm
    #   revoked - deauthorized for other reasons (no alarm)
    # "authorized" stays as the actual access gate (0 = blocked)
    # so existing risk-engine logic doesn't need to change.
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            credential_id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL,
            credential_secret TEXT NOT NULL,
            authorized INTEGER DEFAULT 1,
            status TEXT DEFAULT 'active',
            stolen_reported_at TEXT
        )
    """)

    # Migration for pre-existing databases
    _add_column_if_missing(
        cursor, "credentials", "status", "TEXT DEFAULT 'active'"
    )

    _add_column_if_missing(
        cursor, "credentials", "stolen_reported_at", "TEXT"
    )

    # --------------------------------------------------------
    # CHALLENGES
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            used INTEGER DEFAULT 0
        )
    """)

    # --------------------------------------------------------
    # ACCESS LOGS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            credential_id TEXT,
            user_name TEXT,
            device_id TEXT,
            location_name TEXT,
            decision TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            reason TEXT,
            authentication_result TEXT
        )
    """)

    # ========================================================
    # SEED DEVICES
    # ========================================================

    devices = [
        (
            "READER_001",
            "Ghost Key Reader 1",
            "Chennai Lab A",
            13.0827,
            80.2707,
            "reader_secret_001",
            1
        ),

        (
            "READER_002",
            "Ghost Key Reader 2",
            "Chennai Lab B",
            13.0500,
            80.2100,
            "reader_secret_002",
            1
        )
    ]

    for device in devices:

        cursor.execute("""
            INSERT OR IGNORE INTO devices
            (
                device_id,
                device_name,
                location_name,
                latitude,
                longitude,
                device_secret,
                authorized
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, device)

    # ========================================================
    # SEED CREDENTIALS
    # ========================================================
    # status/stolen_reported_at aren't listed below, so new
    # rows default to status='active' automatically.
    # ========================================================

    credentials = [
        (
            "CARD_001",
            "Authorized User",
            "card_secret_001",
            1
        ),

        (
            "CARD_002",
            "Test User",
            "card_secret_002",
            1
        ),

        (
            "CARD_003",
            "Security Staff",
            "card_secret_003",
            1
        ),

        (
            "CARD_004",
            "Night Shift Manager",
            "card_secret_004",
            1
        ),

        (
            "CARD_999",
            "Unknown Card",
            "unknown_secret",
            0
        )
    ]

    for credential in credentials:

        cursor.execute("""
            INSERT OR IGNORE INTO credentials
            (
                credential_id,
                user_name,
                credential_secret,
                authorized
            )
            VALUES (?, ?, ?, ?)
        """, credential)

    conn.commit()
    conn.close()


# ============================================================
# COMPATIBILITY ALIAS
# ============================================================
# Some versions of the project use init_db().
# Keep both names working.

def init_db():
    initialize_database()


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print("====================================")
    print("Ghost Key Database")
    print("====================================")
    print("Database initialized successfully.")
    print("Database:", DB_PATH)
