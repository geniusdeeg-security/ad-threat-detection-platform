"""
Project 3 — Active Directory Threat Hunting

Provides repeatable hunts against the Project 3 database.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine




HUNTS = {

    "failed_logons":

        """
        SELECT
            username,
            source_ip,
            COUNT(*) AS failures,
            MIN(event_time) AS first_seen,
            MAX(event_time) AS last_seen
        FROM security_events
        WHERE event_id = 4625
        GROUP BY username, source_ip
        ORDER BY failures DESC;
        """,

    "kerberos_rc4":

        """
        SELECT
            id,
            event_time,
            username,
            computer_name,
            event_data->>'TargetUserName' AS target_user,
            event_data->>'ServiceName' AS service_name,
            event_data->>'TicketEncryptionType'
                AS encryption_type
        FROM security_events
        WHERE event_id IN (4768, 4769)
          AND event_data->>'TicketEncryptionType'
              IN ('0x17', '0x00000017')
        ORDER BY event_time DESC;
        """,

    "privileged_changes":

        """
        SELECT
            id,
            event_time,
            event_id,
            computer_name,
            event_data->>'SubjectUserName' AS actor,
            event_data->>'TargetUserName' AS target_group,
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
        ORDER BY event_time DESC;
        """,

    "powershell":

        """
        SELECT
            id,
            event_time,
            computer_name,
            process_name,
            command_line
        FROM sysmon_events
        WHERE event_id = 1
          AND (
              LOWER(COALESCE(process_name, ''))
                  LIKE '%powershell%'
              OR
              LOWER(COALESCE(command_line, ''))
                  LIKE '%powershell%'
          )
        ORDER BY event_time DESC;
        """,

    "lsass_access":

        """
        SELECT
            id,
            event_time,
            computer_name,
            process_name,
            event_data->>'SourceImage' AS source_image,
            event_data->>'TargetImage' AS target_image,
            event_data->>'GrantedAccess' AS granted_access
        FROM sysmon_events
        WHERE event_id = 10
          AND LOWER(
              COALESCE(
                  event_data->>'TargetImage',
                  ''
              )
          ) LIKE '%lsass.exe%'
        ORDER BY event_time DESC;
        """,

    "remote_authentication":

        """
        SELECT
            id,
            event_time,
            username,
            computer_name,
            source_ip,
            event_data->>'LogonType' AS logon_type,
            event_data->>'WorkstationName'
                AS workstation
        FROM security_events
        WHERE event_id = 4624
          AND event_data->>'LogonType' IN ('3', '10')
        ORDER BY event_time DESC;
        """
}


def run_hunt(hunt_name):

    if hunt_name not in HUNTS:
        raise ValueError(
            f"Unknown hunt: {hunt_name}"
        )

    with engine.connect() as conn:

        rows = conn.execute(
            text(HUNTS[hunt_name])
        ).fetchall()

    return rows


def list_hunts():

    return sorted(HUNTS.keys())


if __name__ == "__main__":

    print("=" * 70)
    print("ACTIVE DIRECTORY THREAT HUNTING")
    print("=" * 70)

    print()
    print("Available hunts:")

    for name in list_hunts():
        print(f"  - {name}")

    print()
    print("Running summary hunts...")

    for name in list_hunts():

        try:

            rows = run_hunt(name)

            print(
                f"  {name}: {len(rows)} result(s)"
            )

        except Exception as exc:

            print(
                f"  {name}: ERROR — {exc}"
            )
