"""
Project 3 — Active Directory Attack Path Analysis

Models:

    User
      ↓
    Group
      ↓
    Privilege
      ↓
    Computer

The module derives relationships primarily from Security
Event IDs 4728/4729/4732/4733/4756/4757 and 4624.

It does not require ad_users/ad_computers to be populated.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from database.db_config import engine


PRIVILEGED_GROUPS = {
    "DOMAIN ADMINS": 100,
    "ENTERPRISE ADMINS": 100,
    "SCHEMA ADMINS": 100,
    "SOC-ADMINS": 80,
    "ADMINISTRATORS": 70,
}


def build_attack_paths():

    query = text("""
        SELECT
            event_time,
            event_id,
            computer_name,
            event_data->>'SubjectUserName' AS actor,
            event_data->>'TargetUserName' AS group_name,
            event_data->>'MemberName' AS member_name
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

    paths = []

    with engine.connect() as conn:

        rows = conn.execute(query).fetchall()

        for row in rows:

            group = (
                row.group_name
                or ""
            ).upper()

            member = row.member_name or ""

            matched_group = None
            risk_score = 20

            for privileged_group, score in PRIVILEGED_GROUPS.items():

                if privileged_group in group:

                    matched_group = privileged_group
                    risk_score = score
                    break

            if not matched_group:
                continue

            action = (
                "membership added"
                if row.event_id in (4728, 4732, 4756)
                else "membership removed"
            )

            if action == "membership removed":
                risk_score = max(10, risk_score - 20)

            if risk_score >= 90:
                risk_level = "CRITICAL"
            elif risk_score >= 70:
                risk_level = "HIGH"
            elif risk_score >= 40:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            paths.append({

                "timestamp": str(row.event_time),
                "actor": row.actor,
                "member": member,
                "group": matched_group,
                "computer": row.computer_name,
                "action": action,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "mitre": "T1098",
                "evidence": (
                    f"Event {row.event_id}: {row.actor} "
                    f"{action} '{member}' "
                    f"for '{matched_group}'."
                )
            })

    return paths


def summarize_attack_paths():

    paths = build_attack_paths()

    summary = {

        "total_paths": len(paths),

        "critical": sum(
            1 for p in paths
            if p["risk_level"] == "CRITICAL"
        ),

        "high": sum(
            1 for p in paths
            if p["risk_level"] == "HIGH"
        ),

        "medium": sum(
            1 for p in paths
            if p["risk_level"] == "MEDIUM"
        ),

        "low": sum(
            1 for p in paths
            if p["risk_level"] == "LOW"
        )
    }

    return summary


if __name__ == "__main__":

    paths = build_attack_paths()

    print("=" * 70)
    print("ACTIVE DIRECTORY ATTACK PATH ANALYSIS")
    print("=" * 70)

    print(f"Paths found: {len(paths)}")

    for path in paths[:50]:

        print()
        print(
            f"[{path['risk_level']}] "
            f"{path['actor']} -> "
            f"{path['member']} -> "
            f"{path['group']}"
        )

        print(f"    Action: {path['action']}")
        print(f"    Computer: {path['computer']}")
        print(f"    Risk score: {path['risk_score']}")
        print(f"    MITRE ATT&CK: {path['mitre']}")
        print(f"    Evidence: {path['evidence']}")
