import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import os

SECURITY_LOG = "logs/security/Security.evtx"

print("Reading Security events...")
print()

# =========================================================
# HELPERS
# =========================================================

def parse_time(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except Exception:
        return None


def get_event_data(root):
    data = {}

    for element in root.iter():
        tag = element.tag.split("}")[-1]

        if tag == "Data":
            name = element.attrib.get("Name")

            if name:
                data[name] = element.text or ""

    return data


def normalize_user(user):
    if not user:
        return ""

    user = user.strip()

    # Remove domain prefix
    if "\\" in user:
        user = user.split("\\")[-1]

    # Remove UPN suffix
    if "@" in user:
        user = user.split("@")[0]

    return user.lower()


def is_machine_account(user):
    normalized = normalize_user(user)

    return normalized.endswith("$")


def is_system_account(user):
    normalized = normalize_user(user)

    return normalized in {
        "system",
        "local service",
        "network service",
        "dwm-1",
        "iusr"
    }


def is_privileged_account(user):
    normalized = normalize_user(user)

    return normalized in {
        "administrator",
        "krbtgt",
        "admin",
        "domainadmin"
    }


# =========================================================
# STORAGE
# =========================================================

event_4768 = []
event_4769 = []
event_4624 = []
event_4672 = []

tgt_by_user = defaultdict(list)
service_tickets_by_user = defaultdict(list)
logons_by_user = defaultdict(list)

service_counter = Counter()
user_ticket_counter = Counter()

# =========================================================
# READ SECURITY EVTX
# =========================================================

if not os.path.exists(SECURITY_LOG):

    print(f"[ERROR] File not found: {SECURITY_LOG}")
    raise SystemExit(1)


with Evtx(SECURITY_LOG) as log:

    for record in log.records():

        try:

            xml = record.xml()
            root = ET.fromstring(xml)

            event_id = None
            timestamp = None

            for element in root.iter():

                tag = element.tag.split("}")[-1]

                if tag == "EventID":

                    try:
                        event_id = int(element.text)
                    except Exception:
                        pass

                elif tag == "TimeCreated":

                    timestamp = parse_time(
                        element.attrib.get("SystemTime")
                    )

            if event_id is None:
                continue

            data = get_event_data(root)

            # =================================================
            # 4768 — Kerberos TGT
            # =================================================

            if event_id == 4768:

                user = (
                    data.get("TargetUserName")
                    or data.get("TargetUser")
                    or ""
                )

                ip = (
                    data.get("IpAddress")
                    or data.get("ClientAddress")
                    or ""
                )

                item = {
                    "time": timestamp,
                    "user": user,
                    "ip": ip
                }

                event_4768.append(item)

                normalized = normalize_user(user)

                if normalized:

                    tgt_by_user[normalized].append(timestamp)

            # =================================================
            # 4769 — Kerberos Service Ticket
            # =================================================

            elif event_id == 4769:

                user = (
                    data.get("TargetUserName")
                    or data.get("TargetUser")
                    or ""
                )

                service = (
                    data.get("ServiceName")
                    or data.get("ServiceNameTarget")
                    or ""
                )

                ip = (
                    data.get("IpAddress")
                    or data.get("ClientAddress")
                    or ""
                )

                item = {
                    "time": timestamp,
                    "user": user,
                    "service": service,
                    "ip": ip
                }

                event_4769.append(item)

                normalized = normalize_user(user)

                if normalized:

                    service_tickets_by_user[
                        normalized
                    ].append(item)

                    user_ticket_counter[
                        normalized
                    ] += 1

                if service:

                    service_counter[
                        service.lower()
                    ] += 1

            # =================================================
            # 4624 — Successful Logon
            # =================================================

            elif event_id == 4624:

                user = (
                    data.get("TargetUserName")
                    or data.get("SubjectUserName")
                    or ""
                )

                logon_type = data.get(
                    "LogonType",
                    ""
                )

                item = {
                    "time": timestamp,
                    "user": user,
                    "logon_type": logon_type
                }

                event_4624.append(item)

                normalized = normalize_user(user)

                if normalized:

                    logons_by_user[
                        normalized
                    ].append(item)

            # =================================================
            # 4672 — Special Privileges
            # =================================================

            elif event_id == 4672:

                user = (
                    data.get("SubjectUserName")
                    or ""
                )

                event_4672.append({
                    "time": timestamp,
                    "user": user
                })

        except Exception:
            continue


# =========================================================
# REPORT HEADER
# =========================================================

print("=" * 100)
print("PERSISTENCE & BACKDOOR DETECTION REPORT")
print("=" * 100)

print()

print(
    f"Kerberos TGT events (4768)       : {len(event_4768)}"
)

print(
    f"Kerberos service tickets (4769) : {len(event_4769)}"
)

print(
    f"Successful logons (4624)         : {len(event_4624)}"
)

print(
    f"Privileged events (4672)         : {len(event_4672)}"
)


# =========================================================
# KERBEROS ACCOUNT ACTIVITY
# =========================================================

print()
print("=" * 100)
print("KERBEROS ACCOUNT ACTIVITY")
print("=" * 100)

print()

for user, count in user_ticket_counter.most_common():

    if count >= 3:

        print(
            f"{user}: {count} service tickets"
        )


# =========================================================
# GOLDEN TICKET ANALYSIS
# =========================================================

print()
print("=" * 100)
print("GOLDEN TICKET ANALYSIS")
print("=" * 100)

golden_candidates = []

for user, tickets in service_tickets_by_user.items():

    # -----------------------------------------------------
    # Machine accounts are excluded from Golden Ticket
    # scoring because normal DC/computer Kerberos activity
    # can be very high.
    # -----------------------------------------------------

    if is_machine_account(user):
        continue

    if is_system_account(user):
        continue

    # -----------------------------------------------------
    # Only investigate privileged users more aggressively.
    # -----------------------------------------------------

    privileged = is_privileged_account(user)

    for ticket in tickets:

        timestamp = ticket["time"]

        if timestamp is None:
            continue

        # Look for TGT within 10 hours.
        nearby_tgt = False

        for tgt_time in tgt_by_user.get(user, []):

            if tgt_time is None:
                continue

            if abs(timestamp - tgt_time) <= timedelta(
                hours=10
            ):

                nearby_tgt = True
                break

        # -------------------------------------------------
        # Stronger heuristic:
        #
        # privileged user
        # +
        # service ticket
        # +
        # no nearby TGT
        #
        # This is an investigation candidate, NOT proof.
        # -------------------------------------------------

        if privileged and not nearby_tgt:

            golden_candidates.append({
                "user": user,
                "time": timestamp,
                "service": ticket["service"],
                "ip": ticket["ip"]
            })


if golden_candidates:

    print(
        f"[MEDIUM] Potential Golden Ticket candidates: "
        f"{len(golden_candidates)}"
    )

    for item in golden_candidates[:20]:

        print(
            f"User={item['user']} | "
            f"Time={item['time']} | "
            f"Service={item['service']} | "
            f"IP={item['ip']}"
        )

else:

    print(
        "[OK] No strong Golden Ticket candidates detected."
    )


# =========================================================
# PRIVILEGED KERBEROS ACTIVITY
# =========================================================

print()
print("=" * 100)
print("PRIVILEGED KERBEROS ACTIVITY")
print("=" * 100)

privileged_activity = []

for user, tickets in service_tickets_by_user.items():

    if is_privileged_account(user):

        privileged_activity.append(
            (user, len(tickets))
        )


if privileged_activity:

    for user, count in privileged_activity:

        print(
            f"[INFO] {user}: "
            f"{count} Kerberos service tickets"
        )

else:

    print(
        "[INFO] No privileged-account Kerberos "
        "service-ticket activity detected."
    )


# =========================================================
# KERBEROS TICKET BURST
# =========================================================

print()
print("=" * 100)
print("KERBEROS TICKET BURST ANALYSIS")
print("=" * 100)

burst_detections = []

for user, tickets in service_tickets_by_user.items():

    # Ignore machine accounts.
    if is_machine_account(user):
        continue

    timestamps = sorted(
        [
            item["time"]
            for item in tickets
            if item["time"] is not None
        ]
    )

    for i in range(len(timestamps)):

        window_end = (
            timestamps[i]
            + timedelta(minutes=5)
        )

        count = 0

        for timestamp in timestamps[i:]:

            if timestamp <= window_end:
                count += 1
            else:
                break

        if count >= 10:

            burst_detections.append({
                "user": user,
                "time": timestamps[i],
                "count": count
            })

            break


if burst_detections:

    for item in burst_detections:

        print(
            f"[MEDIUM] {item['user']} generated "
            f"{item['count']} Kerberos service tickets "
            f"within 5 minutes"
        )

else:

    print(
        "[OK] No abnormal user Kerberos ticket "
        "bursts detected."
    )


# =========================================================
# SILVER TICKET HEURISTIC
# =========================================================

print()
print("=" * 100)
print("SILVER TICKET ANALYSIS")
print("=" * 100)

silver_candidates = []

for event in event_4769:

    user = normalize_user(
        event["user"]
    )

    service = (
        event["service"]
        or ""
    ).lower()

    timestamp = event["time"]

    if not user or not timestamp:
        continue

    # Ignore machine accounts for the initial heuristic.
    if is_machine_account(user):
        continue

    # Interesting service classes.
    interesting_service = any(
        keyword in service
        for keyword in [
            "cifs/",
            "host/",
            "http/",
            "ldap/",
            "mssql/"
        ]
    )

    if not interesting_service:
        continue

    nearby_tgt = False

    for tgt_time in tgt_by_user.get(user, []):

        if tgt_time is None:
            continue

        if abs(timestamp - tgt_time) <= timedelta(
            hours=10
        ):

            nearby_tgt = True
            break

    if not nearby_tgt:

        silver_candidates.append({
            "user": user,
            "service": event["service"],
            "time": timestamp,
            "ip": event["ip"]
        })


if silver_candidates:

    print(
        f"[LOW/MEDIUM] Potential Silver Ticket "
        f"investigation candidates: "
        f"{len(silver_candidates)}"
    )

    for item in silver_candidates[:20]:

        print(
            f"User={item['user']} | "
            f"Service={item['service']} | "
            f"Time={item['time']} | "
            f"IP={item['ip']}"
        )

else:

    print(
        "[OK] No strong Silver Ticket candidates detected."
    )


# =========================================================
# CORRELATION
# =========================================================

print()
print("=" * 100)
print("PERSISTENCE / BACKDOOR CORRELATION")
print("=" * 100)

indicators = 0

if golden_candidates:

    indicators += 1

    print(
        "[MEDIUM] Potential Golden Ticket indicators"
    )

if burst_detections:

    indicators += 1

    print(
        "[MEDIUM] Abnormal Kerberos ticket burst"
    )

if silver_candidates:

    indicators += 1

    print(
        "[LOW/MEDIUM] Potential Silver Ticket indicators"
    )


print()

print(
    f"Independent persistence indicators: {indicators}"
)

if indicators >= 2:

    print(
        "[HIGH] Multiple Kerberos indicators "
        "require investigation."
    )

elif indicators == 1:

    print(
        "[MEDIUM] One Kerberos persistence indicator "
        "requires investigation."
    )

else:

    print(
        "[OK] No strong Kerberos persistence "
        "indicators detected."
    )


# =========================================================
# DETECTION ENGINEERING NOTES
# =========================================================

print()
print("=" * 100)
print("DETECTION ENGINEERING NOTES")
print("=" * 100)

print(
    "[INFO] Machine accounts are excluded from "
    "Golden/Silver Ticket scoring."
)

print(
    "[INFO] Kerberos ticket bursts are treated as "
    "anomaly indicators, not automatic compromise."
)

print(
    "[INFO] Unmatched 4769 events are treated as "
    "investigation candidates rather than confirmed "
    "Golden Tickets."
)

print(
    "[INFO] Confirmed Golden/Silver Ticket detection "
    "requires additional telemetry and correlation."
)


# =========================================================
# END
# =========================================================

print()
print("=" * 100)
print("END OF PERSISTENCE & BACKDOOR REPORT")
print("=" * 100)
