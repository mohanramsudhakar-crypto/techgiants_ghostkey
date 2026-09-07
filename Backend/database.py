import sqlite3
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ghostkey.db"


def get_connection():

    connection = sqlite3.connect(DB_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def init_database():

    connection = get_connection()

    cursor = connection.cursor()


    

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


   
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (

            credential_id TEXT PRIMARY KEY,

            user_name TEXT NOT NULL,

            credential_secret TEXT NOT NULL,

            authorized INTEGER DEFAULT 1

        )
    """)


    

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS challenges (

            nonce TEXT PRIMARY KEY,

            device_id TEXT NOT NULL,

            created_at TEXT NOT NULL,

            expires_at TEXT NOT NULL,

            used INTEGER DEFAULT 0

        )
    """)


   
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


    cursor.executemany("""
        INSERT OR IGNORE INTO devices
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, devices)


 
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
            "CARD_999",
            "Unknown Card",
            "unknown_secret",
            0
        )

    ]


    cursor.executemany("""
        INSERT OR IGNORE INTO credentials
        VALUES (?, ?, ?, ?)
    """, credentials)


    connection.commit()

    connection.close()


def log_access(
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

    connection = get_connection()


    connection.execute("""
        INSERT INTO access_logs (

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
    """, (

        datetime.now(
            timezone.utc
        ).isoformat(),

        credential_id,

        user_name,

        device_id,

        location_name,

        decision,

        risk_score,

        risk_level,

        reason,

        authentication_result

    ))


    connection.commit()

    connection.close()
