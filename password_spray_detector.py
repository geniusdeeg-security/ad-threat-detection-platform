"""
Project 3 — Password Spray Detection
MITRE ATT&CK: T1110.003
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


USER_THRESHOLD = 5
WINDOW_MINUTES = 10


def detect_password_spray():

    query = text("""
        WITH failures AS (
            SELECT
                id,
                event_time,
                username,
                computer_name,
                source_ip
            FROM security_events
            WHERE event_id = 4625
              AND event_time IS NOT NULL
              AND username IS NOT NULL
              AND source_ip IS NOT NULL
              AND source_ip NOT IN ('127.0.0.1', '::1', '-')
        )

        SELECT
            MAX(id) AS event_id,
            MAX(computer_name) AS computer_name,
            source_ip,
            COUNT(*) AS failed_attempts,
            COUNT(DISTINCT username) AS targeted_users,
            MIN(event_time) AS first_failure,
            MAX(event_time) AS last_failure,
            ARRAY_AGG(DISTINCT username) AS usernames
        FROM failures
        GROUP BY
            source_ip,
            FLOOR(EXTRACT(EPOCH FROM event_time) / 600)

        HAVING COUNT(DISTINCT username) >= :threshold

        ORDER BY targeted_users DESC, failed_attempts DESC;
    """)

    detections = []

    with engine.connect() as conn:

        rows = conn.execute(
            query,
            {"threshold": USER_THRESHOLD}
        ).fetchall()

        for row in rows:

            detections.append({
                "event_id": row.event_id,
                "source_ip": row.source_ip,
                "computer": row.computer_name,
                "failed_attempts": row.failed_attempts,
                "targeted_users": row.targeted_users,
                "first_failure": str(row.first_failure),
                "last_failure": str(row.last_failure),
                "usernames": list(row.usernames or []),
                "severity": "HIGH",
                "mitre": "T1110.003",
                "confidence": 90,
                "reason": (
                    f"Password spray pattern from {row.source_ip}: "
                    f"{row.targeted_users} distinct accounts targeted "
                    f"with {row.failed_attempts} failed logons."
                )
            })

    return detections


if __name__ == "__main__":

    results = detect_password_spray()

    print("=" * 70)
    print("PASSWORD SPRAY DETECTION")
    print("=" * 70)

    print(f"Detections: {len(results)}")

    for item in results:
        print()
        print(f"[{item['severity']}] {item['source_ip']}")
        print(f"    Targeted users: {item['targeted_users']}")
        print(f"    Failed attempts: {item['failed_attempts']}")
        print(f"    First failure: {item['first_failure']}")
        print(f"    Last failure: {item['last_failure']}")
        print(f"    MITRE ATT&CK: {item['mitre']}")
        print(f"    Confidence: {item['confidence']}%")
        print(f"    Reason: {item['reason']}")
