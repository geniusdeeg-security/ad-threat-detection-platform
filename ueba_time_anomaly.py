from pathlib import Path
import sys

# Make the project root available when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


MITRE_TECHNIQUE = "T1078"
CONFIDENCE = 90

# An hour is considered anomalous when it represents
# less than 1% of the user's historical successful logons.
RARE_HOUR_THRESHOLD = 0.01


def detect_time_anomalies():

    detections = []

    query = """
    WITH user_hour_activity AS (

        SELECT
            event_data->>'TargetUserName' AS username,

            EXTRACT(
                HOUR FROM event_time
            )::int AS login_hour,

            COUNT(*) AS hour_count,

            MIN(event_time) AS first_event_time,

            MAX(event_time) AS last_event_time

        FROM security_events

        WHERE event_id = 4624

          AND COALESCE(
              event_data->>'TargetUserName',
              ''
          ) <> ''

          AND event_data->>'TargetUserName' NOT LIKE '%$'

          AND UPPER(
              event_data->>'TargetUserName'
          ) NOT IN (
              'SYSTEM',
              'LOCAL SERVICE',
              'NETWORK SERVICE',
              'ANONYMOUS LOGON',
              'DWM-1',
              'DWM-2',
              'UMFD-0',
              'UMFD-1',
              'UMFD-2',
              'IUSR'
          )

        GROUP BY
            event_data->>'TargetUserName',
            EXTRACT(HOUR FROM event_time)
    ),

    user_totals AS (

        SELECT
            username,
            SUM(hour_count) AS total_logins

        FROM user_hour_activity

        GROUP BY username
    )

    SELECT

        h.username,

        h.login_hour,

        h.hour_count,

        h.first_event_time,

        h.last_event_time,

        u.total_logins,

        ROUND(
            (
                h.hour_count::numeric
                / NULLIF(u.total_logins, 0)
            ) * 100,
            2
        ) AS activity_percentage

    FROM user_hour_activity h

    JOIN user_totals u
        ON h.username = u.username

    WHERE
        h.hour_count::numeric
        / NULLIF(u.total_logins, 0)
        < :threshold

    ORDER BY
        activity_percentage ASC,
        h.login_hour
    """

    with engine.connect() as conn:

        results = conn.execute(
            text(query),
            {
                "threshold": RARE_HOUR_THRESHOLD
            }
        )

        for row in results:

            percentage = float(
                row.activity_percentage
            )

            # Extremely rare activity.
            if percentage < 0.1:
                severity = "HIGH"

            # Rare but not extremely rare.
            else:
                severity = "MEDIUM"

            detections.append({

                "user":
                    row.username,

                "login_hour":
                    row.login_hour,

                "hour_count":
                    row.hour_count,

                "first_event_time":
                    str(row.first_event_time),

                "last_event_time":
                    str(row.last_event_time),

                "total_logins":
                    int(row.total_logins),

                "activity_percentage":
                    percentage,

                "severity":
                    severity,

                "mitre":
                    MITRE_TECHNIQUE,

                "confidence":
                    CONFIDENCE,

                "reason":
                    (
                        f"User {row.username} had "
                        f"{row.hour_count} successful logon(s) "
                        f"during the {row.login_hour:02d}:00 hour. "
                        f"This represents only "
                        f"{percentage}% of the user's "
                        f"historical successful logons."
                    )
            })

    return detections


if __name__ == "__main__":

    results = detect_time_anomalies()

    print("=" * 70)
    print("UEBA TIME ANOMALY DETECTION")
    print("=" * 70)

    print(
        f"Anomalous user/hour combinations: "
        f"{len(results)}"
    )

    for detection in results:

        print()
        print(
            f"[{detection['severity']}] "
            f"{detection['user']} | "
            f"Hour: "
            f"{detection['login_hour']:02d}:00"
        )

        print(
            f"    Logons in this hour: "
            f"{detection['hour_count']}"
        )

        print(
            f"    Historical logons: "
            f"{detection['total_logins']}"
        )

        print(
            f"    Activity percentage: "
            f"{detection['activity_percentage']}%"
        )

        print(
            f"    First event: "
            f"{detection['first_event_time']}"
        )

        print(
            f"    Last event: "
            f"{detection['last_event_time']}"
        )

        print(
            f"    MITRE ATT&CK: "
            f"{detection['mitre']}"
        )

        print(
            f"    Confidence: "
            f"{detection['confidence']}%"
        )

        print(
            f"    Reason: "
            f"{detection['reason']}"
        )
