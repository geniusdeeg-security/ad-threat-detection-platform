import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_config import engine
from sqlalchemy import text


# ============================================================
# PRIVILEGED GROUPS
# ============================================================

PRIVILEGED_GROUPS = [
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "SOC-ADMINS"
]


# ============================================================
# PRIVILEGED GROUP MEMBERSHIP MONITORING
#
# Windows Security Event IDs:
#
# 4728  Member added to global security-enabled group
# 4729  Member removed from global security-enabled group
# 4732  Member added to local security-enabled group
# 4733  Member removed from local security-enabled group
# 4756  Member added to universal security-enabled group
# 4757  Member removed from universal security-enabled group
#
# IMPORTANT:
# source_event_id must contain security_events.id
# (the unique database row ID), NOT event_id (4728, 4729, etc.).
# ============================================================


def detect_privileged_group_changes():

    detections = []

    query = text("""
        SELECT
            id,
            event_time,
            event_id,

            event_data->>'TargetUserName'
                AS target_user,

            event_data->>'MemberName'
                AS member_name,

            event_data->>'SubjectUserName'
                AS subject_user,

            event_data->>'TargetDomainName'
                AS target_domain,

            event_data->>'SubjectDomainName'
                AS subject_domain,

            event_data->>'Computer'
                AS event_computer

        FROM security_events

        WHERE event_id IN (
            4728,
            4729,
            4732,
            4733,
            4756,
            4757
        )

        ORDER BY event_time DESC;
    """)

    with engine.connect() as conn:

        results = conn.execute(query)

        for row in results:

            group_name = (
                row.target_user or ""
            ).strip()

            group_name_upper = group_name.upper()

            # ------------------------------------------------
            # Only monitor configured privileged groups.
            # ------------------------------------------------

            if not any(
                privileged_group in group_name_upper
                for privileged_group in PRIVILEGED_GROUPS
            ):
                continue

            # ------------------------------------------------
            # Determine membership action.
            # ------------------------------------------------

            if row.event_id in (4728, 4732, 4756):

                action = "ADDED"

            elif row.event_id in (4729, 4733, 4757):

                action = "REMOVED"

            else:

                action = "UNKNOWN"

            # ------------------------------------------------
            # Normalize member name.
            #
            # AD often stores MemberName as a full DN:
            #
            # CN=SOC Test User 1,CN=Users,DC=corp,DC=local
            #
            # Keep the original value because it is useful
            # forensic evidence.
            # ------------------------------------------------

            member_name = (
                row.member_name or ""
            ).strip()

            # ------------------------------------------------
            # The SubjectUserName is the actor who performed
            # the privileged group modification.
            #
            # Example:
            #
            # SubjectUserName = Administrator
            # MemberName      = SOC Test User 1
            # TargetUserName   = SOC-Admins
            # ------------------------------------------------

            actor = (
                row.subject_user or ""
            ).strip()

            # ------------------------------------------------
            # Computer name from the event.
            # ------------------------------------------------

            computer_name = (
                row.event_computer or ""
            ).strip()

            # ------------------------------------------------
            # Return the UNIQUE database event ID.
            #
            # This is critical for alert deduplication.
            # ------------------------------------------------

            detections.append({

                "database_event_id": row.id,

                "timestamp": row.event_time,

                "event_id": row.event_id,

                "actor": actor,

                "member": member_name,

                "group": group_name,

                "action": action,

                "target_domain": row.target_domain,

                "subject_domain": row.subject_domain,

                "computer_name": computer_name,

                "severity": "CRITICAL",

                "mitre": "T1098"

            })

    return detections


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    results = detect_privileged_group_changes()

    print()
    print("=" * 70)
    print("PRIVILEGED ACCESS MONITORING")
    print("=" * 70)

    print(
        f"Privileged group changes detected: {len(results)}"
    )

    print()

    for detection in results:

        print(
            f"DB Event ID: {detection['database_event_id']}"
        )

        print(
            f"Windows Event ID: {detection['event_id']}"
        )

        print(
            f"Actor: {detection['actor']}"
        )

        print(
            f"Member: {detection['member']}"
        )

        print(
            f"Group: {detection['group']}"
        )

        print(
            f"Action: {detection['action']}"
        )

        print(
            f"Computer: {detection['computer_name']}"
        )

        print(
            f"MITRE: {detection['mitre']}"
        )

        print("-" * 70)
