import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
from collections import Counter

PATH = "logs/sysmon/Sysmon.evtx"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SUSPICIOUS_IMAGES = {
    "powershell.exe",
    "psexec.exe",
    "schtasks.exe",
    "at.exe",
    "sc.exe",
    "wmic.exe",
    "wmiprvse.exe",
}

HIGH_RISK_KEYWORDS = [
    "invoke-command",
    "invoke-wmimethod",
    "invoke-cimmethod",
    "new-pssession",
    "enter-pssession",
    "win32_process",
    "create",
    "start-service",
    "stop-service",
    "sc.exe create",
    "sc.exe start",
    "schtasks /create",
    "psexec",
    "powershell -enc",
    "powershell.exe -enc",
    "encodedcommand",
]

counts = Counter()
detections = []

print("Reading Sysmon Event ID 1 events...")
print("Analyzing scheduled task / WMI / service administration activity...")
print()

with evtx.Evtx(PATH) as log:

    for record in log.records():

        try:
            root = ET.fromstring(record.xml())

            event_id = root.find(f".//{NS}EventID")

            if event_id is None or event_id.text != "1":
                continue

            data = {}

            for item in root.findall(f".//{NS}EventData/{NS}Data"):
                name = item.attrib.get("Name")
                data[name] = item.text or ""

            image = data.get("Image", "")
            command = data.get("CommandLine", "")
            user = data.get("User", "")
            parent = data.get("ParentImage", "")
            parent_command = data.get("ParentCommandLine", "")
            timestamp = data.get("UtcTime", "")

            image_name = image.lower().split("\\")[-1]
            command_lower = command.lower()

            if image_name not in SUSPICIOUS_IMAGES:
                continue

            counts[image_name] += 1

            risk_reasons = []

            # -------------------------------------------------
            # PowerShell
            # -------------------------------------------------

            if image_name == "powershell.exe":

                for keyword in HIGH_RISK_KEYWORDS:

                    if keyword in command_lower:

                        risk_reasons.append(
                            f"PowerShell suspicious keyword: {keyword}"
                        )

                if "-enc" in command_lower or "encodedcommand" in command_lower:
                    risk_reasons.append(
                        "Encoded PowerShell command"
                    )

                if user.lower() == "corp\\administrator":
                    risk_reasons.append(
                        "Executed by privileged account"
                    )

            # -------------------------------------------------
            # PsExec
            # -------------------------------------------------

            elif image_name == "psexec.exe":

                risk_reasons.append(
                    "PsExec execution detected"
                )

            # -------------------------------------------------
            # Scheduled Tasks
            # -------------------------------------------------

            elif image_name == "schtasks.exe":

                if "/create" in command_lower:
                    risk_reasons.append(
                        "Scheduled task creation"
                    )

            # -------------------------------------------------
            # Service Control
            # -------------------------------------------------

            elif image_name == "sc.exe":

                if "create" in command_lower:
                    risk_reasons.append(
                        "Windows service creation"
                    )

                elif "start" in command_lower:
                    risk_reasons.append(
                        "Windows service start"
                    )

            # -------------------------------------------------
            # WMI
            # -------------------------------------------------

            elif image_name == "wmiprvse.exe":

                # Ordinary WMI provider startup is normally benign.
                # Only flag it when stronger evidence is present.
                if user.lower() == "corp\\administrator":
                    risk_reasons.append(
                        "WMI provider executed under privileged user"
                    )

                if any(
                    keyword in command_lower
                    for keyword in HIGH_RISK_KEYWORDS
                ):
                    risk_reasons.append(
                        "WMI command contains suspicious activity"
                    )

            # -------------------------------------------------
            # Store only events with actual risk indicators
            # -------------------------------------------------

            if risk_reasons:

                detections.append({
                    "time": timestamp,
                    "user": user,
                    "image": image,
                    "command": command,
                    "parent": parent,
                    "parent_command": parent_command,
                    "reasons": risk_reasons,
                })

        except Exception:
            pass


print("=" * 90)
print("ADMINISTRATION TOOL ABUSE DETECTION REPORT")
print("=" * 90)

print()
print("TELEMETRY SUMMARY")
print("-" * 90)

for name in sorted(counts):
    print(f"{name:<25}: {counts[name]}")

print()
print(f"Total administration-tool executions: {sum(counts.values())}")

print()
print("=" * 90)
print("HIGH-RISK ADMINISTRATION ACTIVITY")
print("=" * 90)

print()

if not detections:

    print("[OK] No high-confidence administration-tool abuse detected.")

else:

    print(f"[WARNING] {len(detections)} suspicious administration events detected.")
    print()

    for i, detection in enumerate(detections, 1):

        print("-" * 90)
        print(f"Detection #{i}")
        print(f"Time          : {detection['time']}")
        print(f"User          : {detection['user']}")
        print(f"Image         : {detection['image']}")
        print(f"CommandLine   : {detection['command']}")
        print(f"ParentImage   : {detection['parent']}")
        print(f"ParentCommand : {detection['parent_command']}")

        print("Risk Factors  :")

        for reason in detection["reasons"]:
            print(f"  - {reason}")

print()
print("=" * 90)
print("MITRE ATT&CK MAPPING")
print("=" * 90)

print("T1059.001 - PowerShell")
print("T1047     - Windows Management Instrumentation")
print("T1543.003 - Windows Service")
print("T1053.005 - Scheduled Task/Job: Scheduled Task")
print("T1569.002 - System Services: Service Execution")

print()
print("=" * 90)
print("DETECTION ENGINEERING NOTES")
print("=" * 90)

print("[INFO] Normal WMI provider activity is not automatically malicious.")
print("[INFO] Suspicious command lines increase detection confidence.")
print("[INFO] Privileged-user execution increases detection priority.")
print("[INFO] Service creation and scheduled-task creation require additional correlation.")
print("[INFO] PowerShell encoded commands are treated as higher-risk telemetry.")

print()
print("=" * 90)
print("END OF ADMINISTRATION TOOL ABUSE REPORT")
print("=" * 90)
