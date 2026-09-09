import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "database"))

from db_config import engine
from sqlalchemy import text

# ============================================================
# DCSYNC DETECTION
# MITRE ATT&CK: T1003.006
# ============================================================

# Microsoft Active Directory replication extended rights
REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "19195a5b-6da0-11d0-afd3-00c04fd930c9",
}

# Legitimate domain controller accounts in this lab
EXPECTED_DC_ACCOUNTS = {
    "DC01$",
}

MITRE_TECHNIQUE = "T1003.006"
MITRE_NAME = "DCSync"
CONFIDENCE = 95


# ============================================================
# CHECK FOR REPLICATION RIGHTS
# ============================================================

def is_replication_event(properties):

    if not properties:
        return False

    properties_lower = properties.lower()

    return any(
        guid in properties_lower
        for guid in REPLICATION_GUIDS
    )


# ============================================================
# CHECK WHETHER ALERT ALREADY EXISTS
# ============================================================

def alert_already_exists(source_event_id):

    query = text("""
        SELECT id
        FROM alerts
        WHERE source_event_id = :source_event_id
          AND alert_name = 'DCSync Activity'
        LIMIT 1;
    """)

    with engine.connect() as connection:

        result = connection.execute(
            query,
            {
                "source_event_id": source_event_id
            }
        )

        return result.first() is not None


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(
    source_event_id,
    username,
    computer_name,
    description
):

    if alert_already_exists(source_event_id):

        return None

    query = text("""
        INSERT INTO alerts (
            severity,
            alert_name,
            source_event_id,
            username,
            computer_name,
            description
        )
        VALUES (
            'CRITICAL',
            'DCSync Activity',
            :source_event_id,
            :username,
            :computer_name,
            :description
        )
        RETURNING id;
    """)

    with engine.begin() as connection:

        result = connection.execute(
            query,
            {
                "source_event_id": source_event_id,
                "username": username,
                "computer_name": computer_name,
                "description": description,
            }
        )

        return result.scalar_one()


# ============================================================
# CREATE MITRE DETECTION RESULT
# ============================================================

def create_detection_result(alert_id):

    query = text("""
        INSERT INTO detection_results (
            alert_id,
            technique_id,
            confidence_score
        )
        VALUES (
            :alert_id,
            :technique_id,
            :confidence_score
        );
    """)

    with engine.begin() as connection:

        connection.execute(
            query,
            {
                "alert_id": alert_id,
                "technique_id": MITRE_TECHNIQUE,
                "confidence_score": CONFIDENCE,
            }
        )


# ============================================================
# MAIN DCSYNC DETECTOR
# ============================================================

def detect_dcsync():

    query = text("""
        SELECT
            id,
            event_time,
            username,
            computer_name,
            event_data
        FROM security_events
        WHERE event_id = 4662
          AND event_data->>'ObjectServer' = 'DS'
        ORDER BY event_time;
    """)

    detections = []
    replication_events = 0
    ignored_dc_events = 0

    with engine.connect() as connection:

        results = connection.execute(query)

        for row in results:

            event_data = row.event_data

            if isinstance(event_data, str):

                event_data = json.loads(event_data)

            subject_user = (
                event_data.get("SubjectUserName")
                or row.username
            )

            properties = event_data.get(
                "Properties",
                ""
            )

            # ------------------------------------------------
            # Check replication GUID
            # ------------------------------------------------

            if not is_replication_event(properties):

                continue

            replication_events += 1

            # ------------------------------------------------
            # Ignore legitimate DC replication
            # ------------------------------------------------

            if subject_user.upper() in EXPECTED_DC_ACCOUNTS:

                ignored_dc_events += 1

                continue

            # ------------------------------------------------
            # Suspicious replication activity
            # ------------------------------------------------

            detections.append({
                "database_id": row.id,
                "event_time": row.event_time,
                "username": subject_user,
                "computer_name": row.computer_name,
            })

    return (
        replication_events,
        ignored_dc_events,
        detections,
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():

    print("=" * 70)
    print("DCSYNC DETECTION ENGINE")
    print("=" * 70)

    (
        replication_events,
        ignored_dc_events,
        detections,
    ) = detect_dcsync()

    print()
    print(
        f"Replication events detected: "
        f"{replication_events}"
    )

    print(
        f"Legitimate DC events ignored: "
        f"{ignored_dc_events}"
    )

    print(
        f"Suspicious replication events: "
        f"{len(detections)}"
    )

    print()

    # ========================================================
    # PROCESS SUSPICIOUS EVENTS
    # ========================================================

    alerts_created = 0
    duplicates = 0

    for detection in detections:

        description = (
            "Potential DCSync activity detected. "
            "A non-domain-controller account performed "
            "Active Directory replication-related access "
            f"on {detection['computer_name']}. "
            f"Account: {detection['username']}. "
            "MITRE ATT&CK technique: T1003.006."
        )

        alert_id = create_alert(
            source_event_id=detection["database_id"],
            username=detection["username"],
            computer_name=detection["computer_name"],
            description=description,
        )

        if alert_id is None:

            duplicates += 1

            print(
                f"  Duplicate DCSync alert skipped "
                f"for event {detection['database_id']}"
            )

            continue

        create_detection_result(alert_id)

        alerts_created += 1

        print("-" * 70)

        print(
            f"  🚨 DCSync ALERT {alert_id}"
        )

        print(
            f"  Database ID : "
            f"{detection['database_id']}"
        )

        print(
            f"  Time        : "
            f"{detection['event_time']}"
        )

        print(
            f"  Account     : "
            f"{detection['username']}"
        )

        print(
            f"  Computer    : "
            f"{detection['computer_name']}"
        )

        print(
            f"  Severity    : CRITICAL"
        )

        print(
            f"  MITRE       : "
            f"{MITRE_TECHNIQUE} ({MITRE_NAME})"
        )

        print(
            f"  Confidence  : "
            f"{CONFIDENCE}%"
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("DCSYNC DETECTION SUMMARY")
    print("=" * 70)

    print(
        f"Replication events : "
        f"{replication_events}"
    )

    print(
        f"Legitimate DC      : "
        f"{ignored_dc_events}"
    )

    print(
        f"Suspicious events  : "
        f"{len(detections)}"
    )

    print(
        f"Alerts created     : "
        f"{alerts_created}"
    )

    print(
        f"Duplicates skipped : "
        f"{duplicates}"
    )

    print(
        f"MITRE technique    : "
        f"{MITRE_TECHNIQUE}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
