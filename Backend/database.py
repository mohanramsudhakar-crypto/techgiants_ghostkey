import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / 'ghostkey.db'

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():

    conn = get_connection()

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        employee_code TEXT UNIQUE NOT NULL,
        credential_uid TEXT UNIQUE NOT NULL,
        credential_secret TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE'

    );

    CREATE TABLE IF NOT EXISTS zones (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT UNIQUE NOT NULL,
       latitude REAL NOT NULL,
       longitude REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       device_id TEXT UNIQUE NOT NULL,
       zone_id INTEGER NOT NULL,
       device_secret TEXT NOT NULL,
       status TEXT DEFAULT 'ACTIVE',
       FOREIGN KEY(zone_id) REFERENCES zones(id)   
    );

    CREATE TABLE IF NOT EXISTS challenges (
       nonce TEXT PRIMARY KEY, 
       device-id TEXT NOT NULL,
       created_at INTEGER NOT NULL, 
       used INTEGER DEFAULT 0
     );

     CREATE TABLE IF NOT EXISTS access-logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        employee_code TEXT,
        device_id TEXT NOT NULL,
        zone TEXT NOT NULL,
        result TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        reason TEXT NOT NULL,
        nonce TEXT
    );
    """)

    conn.commit()
    conn.close()

