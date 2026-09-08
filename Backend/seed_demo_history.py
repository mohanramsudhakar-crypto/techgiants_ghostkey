"""
DEMO HELPER - not part of the running app, run this by hand once
before demoing the behavioral-context feature.

It writes a few fake "ALLOW" rows into access_logs for CARD_001,
all tagged with hours that are deliberately different from
whatever time it is right now, and all on READER_001. That gives
CARD_001 an established "normal pattern" (same device, hours far
from now) BEFORE you do a single live scan - which is exactly the
history get_behavioral_history() in app.py needs (it requires at
least MIN_HISTORY_FOR_BEHAVIOR_CHECK = 3 past ALLOW rows before it
will flag anything at all).

Because the seeded hours are computed relative to the current
time (current_hour + 5, +6, +7, wrapped mod 24), this works
correctly no matter what time of day you actually run the demo -
you never have to change your system clock.

Usage:
    cd backend
    python seed_demo_history.py

Safe to run with app.py already running - it opens its own short
sqlite connection (same pattern database.py uses) and closes it
immediately, same as every request Flask handles.
"""

from datetime import datetime, timezone, timedelta

from database import get_connection, initialize_database


CREDENTIAL_ID = "CARD_001"
USER_NAME = "Authorized User"
BASELINE_DEVICE_ID = "READER_001"
BASELINE_LOCATION = "Chennai Lab A"

# Must match LOCAL_TZ_OFFSET in app.py so the seeded hours line up
# with what the app will compute when it reads them back.
LOCAL_TZ_OFFSET = timedelta(hours=5, minutes=30)


def seed():

    # Safe to call even if the DB already exists - only creates
    # tables/columns that are missing, doesn't wipe anything.
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    now_utc = datetime.now(timezone.utc)
    now_local = now_utc + LOCAL_TZ_OFFSET
    current_hour = now_local.hour

    print(f"Current local hour right now: {current_hour}:00")

    # Clean up any previous demo seed rows so re-running this
    # script doesn't pile up duplicates.
    cursor.execute(
        """
        DELETE FROM access_logs
        WHERE credential_id = ? AND reason = 'DEMO_SEED'
        """,
        (CREDENTIAL_ID,)
    )

    seeded_hours = []

    # +5, +6, +7 hours from now, wrapped into 0-23. None of these
    # can ever equal current_hour, so "unusual_time" is guaranteed
    # to fire on the live scan regardless of when you run this.
    for offset in (5, 6, 7):

        seed_hour = (current_hour + offset) % 24
        seeded_hours.append(seed_hour)

        # "Yesterday" at seed_hour, in local time, then converted
        # back to a true UTC instant - matches how app.py stores
        # and later re-reads timestamps.
        fake_local_time = now_local.replace(
            hour=seed_hour,
            minute=0,
            second=0,
            microsecond=0
        ) - timedelta(days=1)

        fake_utc_time = fake_local_time - LOCAL_TZ_OFFSET

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
            VALUES (?, ?, ?, ?, ?, 'ALLOW', 0, 'LOW', 'DEMO_SEED', 'AUTHENTICATED')
            """,
            (
                fake_utc_time.isoformat(),
                CREDENTIAL_ID,
                USER_NAME,
                BASELINE_DEVICE_ID,
                BASELINE_LOCATION
            )
        )

    conn.commit()
    conn.close()

    print(f"Seeded 3 past ALLOW accesses for {CREDENTIAL_ID}")
    print(f"  Historical device: {BASELINE_DEVICE_ID}")
    print(f"  Historical hours:  {sorted(seeded_hours)} (local)")
    print()
    print("Now scan CARD_001 live and watch the Reason column:")
    print(f"  - On {BASELINE_DEVICE_ID} right now ({current_hour}:00)")
    print("      -> same device, different hour -> 'unusual time' flag")
    print("  - On READER_002 (any hour)")
    print("      -> different device -> 'unfamiliar device' flag")
    print("      -> (+ unusual time too, since 002 was never used before)")
    print()
    print("Either way: access should still be ALLOWED (door opens),")
    print("just with a higher risk score and a visible reason.")


if __name__ == "__main__":
    seed()
