"""
Project 3 — Lateral Movement Detection

MITRE ATT&CK:
    T1021.001 — RDP
    T1021.002 — SMB/Windows Admin Shares
    T1021.006 — Windows Remote Management
    T1550.002 — Pass the Hash

The detector intentionally avoids treating every Windows
network logon as malicious.
"""

from pathlib import Path
import sys
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


REMOTE_LOGON_TYPES = {"3", "10"}

REMOTE_PORTS = {
    "135",
    "139",
    "445",
    "3389",
    "5985",
    "5986",
}

IGNORED_USERS = {
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
}

IGNORED_IPS = {
    "::1",
    "127.0.0.1",
    "-",
    "",
}


def _load_event_data(value):

    if isinstance(value, dict):
        return value

    if isinstance(value, str):

        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}

    return {}


def detect_lateral_movement():

    query = text("""
        SELECT
            id,
            event_time,
            username,
            computer_name,
            source_ip,
            event_data
        FROM security_events
        WHERE event_id = 4624
          AND event_time IS NOT NULL
        ORDER BY event_time DESC;
    """)

    detections = []

    with engine.connect() as conn:

        rows = conn.execute(query).fetchall()

        for row in rows:

            data = _load_event_data(row.event_data)

            logon_type = str(
                data.get("LogonType", "")
            )

            if logon_type not in REMOTE_LOGON_TYPES:
                continue

            username = (
                data.get("TargetUserName")
                or row.username
                or ""
            )

            username_upper = username.upper()

            if username_upper in IGNORED_USERS:
                continue

            if username_upper.endswith("$"):
                continue

            source_ip = (
                data.get("IpAddress")
                or row.source_ip
                or ""
            )

            if source_ip in IGNORED_IPS:
                continue

            if source_ip.lower().startswith("fe80:"):
                continue

            workstation = (
                data.get("WorkstationName")
                or ""
            )

            # Network logons without a workstation are
            # generally weak evidence.
            if logon_type == "3" and not workstation:
                continue

            # A human account remotely authenticating is
            # stronger evidence than machine-to-machine auth.
            detections.append({

                "event_id": row.id,
                "event_time": str(row.event_time),
                "username": username,
                "source_ip": source_ip,
                "destination_computer": row.computer_name,
                "workstation": workstation,
                "logon_type": logon_type,
                "severity": "HIGH",
                "mitre": (
                    "T1021.001"
                    if logon_type == "10"
                    else "T1021.002"
                ),
                "confidence": 70,
                "reason": (
                    f"Human account '{username}' performed "
                    f"remote LogonType {logon_type} authentication "
                    f"from {source_ip} to {row.computer_name}."
                )
            })

    return detections


if __name__ == "__main__":

    results = detect_lateral_movement()

    print("=" * 70)
    print("LATERAL MOVEMENT DETECTION")
    print("=" * 70)

    print(f"Remote authentication candidates: {len(results)}")

    for item in results[:50]:

        print()
        print(
            f"[{item['severity']}] "
            f"{item['username']} "
            f"{item['source_ip']} -> "
            f"{item['destination_computer']}"
        )

        print(f"    Logon type: {item['logon_type']}")
        print(f"    Workstation: {item['workstation']}")
        print(f"    MITRE ATT&CK: {item['mitre']}")
        print(f"    Confidence: {item['confidence']}%")
        print(f"    Reason: {item['reason']}")
