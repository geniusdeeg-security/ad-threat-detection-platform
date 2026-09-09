from pathlib import Path
import sys

# Make the project root available when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


MITRE_TECHNIQUE = "T1098"
CONFIDENCE = 90

# Privileged groups monitored by the detector.
PRIVILEGED_GROUPS = (
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "SOC-ADMINS"
)

# Add/remove activity within this period is considered
# rapid privileged-group modification.
RAPID_CHANGE_SECONDS = 60


def detect_admin_behavior_changes():

    detections = []

    query = """
    WITH privileged_changes AS (

        SELECT
            id,
            event_id,
            event_time,
            computer_name,

            event_data->>'SubjectUserName' AS actor,

            UPPER(
                event_data->>'TargetUserName'
            ) AS target_group,

            event_data->>'MemberName' AS member

        FROM security_events

        WHERE event_id IN (
            4728,
            4729,
            4732,
            4733,
            4756,
            4757
        )

        AND UPPER(
            COALESCE(
                event_data->>'TargetUserName',
                ''
            )
        ) IN (
            'DOMAIN ADMINS',
            'ENTERPRISE ADMINS',
            'SCHEMA ADMINS',
            'SOC-ADMINS'
        )
    ),

    paired_changes AS (

        SELECT
            add_event.id AS add_id,
            add_event.event_time AS add_time,
            add_event.computer_name AS add_computer,
            add_event.actor AS add_actor,
            add_event.target_group AS add_group,
            add_event.member AS add_member,

            remove_event.id AS remove_id,
            remove_event.event_time AS remove_time,
            remove_event.computer_name AS remove_computer,
            remove_event.actor AS remove_actor,
            remove_event.target_group AS remove_group,
            remove_event.member AS remove_member,

            EXTRACT(
                EPOCH FROM (
                    remove_event.event_time
                    - add_event.event_time
                )
            ) AS seconds_between_changes

        FROM privileged_changes add_event

        JOIN privileged_changes remove_event
            ON remove_event.event_id IN (
                4729,
                4733,
                4757
            )

            AND add_event.event_id IN (
                4728,
                4732,
                4756
            )

            AND remove_event.member =
                add_event.member

            AND remove_event.target_group =
                add_event.target_group

            AND remove_event.event_time >
                add_event.event_time

            AND remove_event.event_time <=
                add_event.event_time
                + INTERVAL '60 seconds'
    )

    SELECT *

    FROM paired_changes

    ORDER BY add_time
    """

    with engine.connect() as conn:

        results = conn.execute(text(query))

        for row in results:

            seconds = float(
                row.seconds_between_changes
            )

            detections.append({

                "actor":
                    row.add_actor,

                "member":
                    row.add_member,

                "group":
                    row.add_group,

                "computer":
                    row.add_computer,

                "add_time":
                    str(row.add_time),

                "remove_time":
                    str(row.remove_time),

                "seconds_between_changes":
                    round(seconds, 2),

                "severity":
                    "HIGH",

                "mitre":
                    MITRE_TECHNIQUE,

                "confidence":
                    CONFIDENCE,

                "reason":
                    (
                        f"Privileged account {row.add_actor} "
                        f"added {row.add_member} to "
                        f"{row.add_group} and removed the "
                        f"same member {round(seconds, 2)} "
                        f"seconds later."
                    )
            })

    return detections


if __name__ == "__main__":

    results = detect_admin_behavior_changes()

    print("=" * 70)
    print("UEBA ADMIN BEHAVIOR CHANGE DETECTION")
    print("=" * 70)

    print(
        f"Behavior changes detected: "
        f"{len(results)}"
    )

    for detection in results:

        print()
        print(
            f"[{detection['severity']}] "
            f"{detection['actor']}"
        )

        print(
            f"    Group: "
            f"{detection['group']}"
        )

        print(
            f"    Member: "
            f"{detection['member']}"
        )

        print(
            f"    Computer: "
            f"{detection['computer']}"
        )

        print(
            f"    Added: "
            f"{detection['add_time']}"
        )

        print(
            f"    Removed: "
            f"{detection['remove_time']}"
        )

        print(
            f"    Time between changes: "
            f"{detection['seconds_between_changes']} seconds"
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
