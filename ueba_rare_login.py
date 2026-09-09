from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


MITRE_TECHNIQUE = "T1078"
CONFIDENCE = 75


def detect_rare_logins():

    detections = []

    query = """
    WITH user_computer_history AS (

        SELECT
            event_data->>'TargetUserName' AS username,
            computer_name,
            MIN(event_time) AS first_seen,
            COUNT(*) AS login_count

        FROM security_events

        WHERE event_id = 4624

          AND COALESCE(
              event_data->>'TargetUserName',
              ''
          ) <> ''

        GROUP BY
            event_data->>'TargetUserName',
            computer_name
    )

    SELECT *

    FROM user_computer_history

    WHERE login_count = 1
    """

    with engine.connect() as conn:

        results = conn.execute(text(query))

        for row in results:

            detections.append({

                "user":
                    row.username,

                "computer":
                    row.computer_name,

                "first_seen":
                    str(row.first_seen),

                "severity":
                    "MEDIUM",

                "mitre":
                    MITRE_TECHNIQUE,

                "confidence":
                    CONFIDENCE

            })

    return detections


if __name__ == "__main__":

    results = detect_rare_logins()

    print("=" * 70)
    print("UEBA RARE LOGIN DETECTION")
    print("=" * 70)

    print(
        f"Rare logins detected: "
        f"{len(results)}"
    )

    for detection in results:

        print()
        print(
            f"[{detection['severity']}] "
            f"{detection['user']} | "
            f"{detection['computer']}"
        )

        print(
            f"    First seen: "
            f"{detection['first_seen']}"
        )

        print(
            f"    MITRE ATT&CK: "
            f"{detection['mitre']}"
        )

        print(
            f"    Confidence: "
            f"{detection['confidence']}%"
        )
