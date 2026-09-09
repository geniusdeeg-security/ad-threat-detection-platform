from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import psycopg2
from getpass import getpass
import hashlib

# ============================================================
# CONFIGURATION
# ============================================================

EVTX_FILE = "logs/security/Security.evtx"

DB_NAME = "active_directory_db"
DB_USER = "threat_user"
DB_HOST = "localhost"

KERBEROS_EVENTS = [4768, 4769]


# ============================================================
# PARSE KERBEROS EVENTS
# ============================================================

events = []

print("\nReading Kerberos Events...\n")

with Evtx(EVTX_FILE) as log:

    for record in log.records():

        try:

            root = ET.fromstring(record.xml())

            event_id = None
            timestamp = None
            data = {}

            # ------------------------------------------------
            # Extract System fields and EventData
            # ------------------------------------------------

            for element in root.iter():

                if element.tag.endswith("EventID"):

                    if element.text:
                        event_id = int(element.text)

                elif element.tag.endswith("TimeCreated"):

                    timestamp = element.attrib.get("SystemTime")

                elif element.tag.endswith("Data"):

                    name = element.attrib.get("Name")

                    if name:
                        data[name] = element.text

            # ------------------------------------------------
            # Only process Kerberos events
            # ------------------------------------------------

            if event_id not in KERBEROS_EVENTS:
                continue

            # =================================================
            # EVENT 4768 — TGT REQUEST
            # =================================================

            if event_id == 4768:

                events.append(
                    {
                        "timestamp": timestamp,
                        "username": data.get("TargetUserName"),
                        "service_name": "krbtgt",
                        "source_ip": data.get("IpAddress"),
                        "encryption_type": data.get("TicketEncryptionType"),
                        "pre_auth_type": data.get("PreAuthType"),
                        "ticket_options": data.get("TicketOptions"),
                        "target_domain": data.get("TargetDomainName"),
                        "event_id": 4768,
                        "ticket_type": "TGT",
                    }
                )

            # =================================================
            # EVENT 4769 — TGS REQUEST
            # =================================================

            elif event_id == 4769:

                events.append(
                    {
                        "timestamp": timestamp,
                        "username": data.get("TargetUserName"),
                        "service_name": data.get("ServiceName"),
                        "source_ip": data.get("IpAddress"),
                        "encryption_type": data.get("TicketEncryptionType"),
                        "pre_auth_type": None,
                        "ticket_options": data.get("TicketOptions"),
                        "target_domain": data.get("TargetDomainName"),
                        "event_id": 4769,
                        "ticket_type": "TGS",
                    }
                )

        except Exception as e:

            print(f"Parser error: {e}")


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("=" * 100)
print("KERBEROS EVENTS")
print("=" * 100)

for event in events[:20]:

    print(
        f"\nTime          : {event['timestamp']}"
        f"\nUsername      : {event['username']}"
        f"\nService       : {event['service_name']}"
        f"\nSource IP     : {event['source_ip']}"
        f"\nEvent ID      : {event['event_id']}"
        f"\nTicket Type   : {event['ticket_type']}"
        f"\nEncryption    : {event['encryption_type']}"
        f"\nPreAuth Type  : {event['pre_auth_type']}"
        f"\nTicket Options: {event['ticket_options']}"
        f"\nDomain        : {event['target_domain']}"
    )

print(f"\nTotal Kerberos Events: {len(events)}")


# ============================================================
# POSTGRESQL
# ============================================================

if events:

    print("\nConnecting to PostgreSQL...")

    password = getpass("PostgreSQL password: ")

    try:

        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=password,
        )

        cursor = conn.cursor()

        inserted = 0
        duplicates = 0

        # ====================================================
        # PROCESS EVENTS
        # ====================================================

        for event in events:

            # ------------------------------------------------
            # CREATE DETERMINISTIC EVENT HASH
            # ------------------------------------------------

            event_hash = hashlib.sha256(
                (
                    str(event["timestamp"])
                    + str(event["username"])
                    + str(event["service_name"])
                    + str(event["source_ip"])
                    + str(event["event_id"])
                    + str(event["ticket_type"])
                    + str(event["encryption_type"])
                    + str(event["pre_auth_type"])
                    + str(event["ticket_options"])
                    + str(event["target_domain"])
                ).encode()
            ).hexdigest()

            # ------------------------------------------------
            # CHECK FOR EXISTING EVENT
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT id
                FROM kerberos_events
                WHERE event_hash = %s
                """,
                (event_hash,),
            )

            existing = cursor.fetchone()

            if existing:

                duplicates += 1

                print(
                    f"[-] Duplicate ignored: "
                    f"{event['username']} | "
                    f"{event['event_id']} | "
                    f"{event['service_name']}"
                )

                continue

            # ------------------------------------------------
            # INSERT EVENT
            # ------------------------------------------------

            cursor.execute(
                """
                INSERT INTO kerberos_events
                (
                    timestamp,
                    username,
                    service_name,
                    source_ip,
                    event_id,
                    ticket_type,
                    encryption_type,
                    pre_auth_type,
                    ticket_options,
                    target_domain,
                    event_hash
                )
                VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                )
                """,
                (
                    event["timestamp"],
                    event["username"],
                    event["service_name"],
                    event["source_ip"],
                    event["event_id"],
                    event["ticket_type"],
                    event["encryption_type"],
                    event["pre_auth_type"],
                    event["ticket_options"],
                    event["target_domain"],
                    event_hash,
                ),
            )

            inserted += 1

        # ----------------------------------------------------
        # COMMIT
        # ----------------------------------------------------

        conn.commit()

        cursor.close()
        conn.close()

        print("\n" + "=" * 80)
        print("KERBEROS DATABASE IMPORT")
        print("=" * 80)

        print(f"[+] Inserted:    {inserted}")
        print(f"[-] Duplicates:  {duplicates}")
        print(f"[+] Total read:  {len(events)}")

    except Exception as e:

        print(f"\n[!] PostgreSQL error: {e}")

else:

    print("\n[+] No Kerberos events found.")
