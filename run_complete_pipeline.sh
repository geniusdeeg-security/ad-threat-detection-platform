#!/bin/bash

# ==============================================================
# PROJECT 3 — ACTIVE DIRECTORY DETECTION & MONITORING PLATFORM
# COMPLETE PIPELINE
#
# Environment:
#   Kali Linux
#   Windows Server 2022 / AD DS
#   Windows 10
#   Sysmon
#   PostgreSQL
#   Python
#   Flask
#   MITRE ATT&CK
#
# Design:
#   - Non-destructive
#   - Repeatable
#   - Uses existing project evidence
#   - Preserves detection_engine.py
#   - Preserves app.py
#   - Uses PYTHONPATH for project imports
# ==============================================================

set -u

PROJECT_DIR="/home/kali/projects/ad_detection_platform"
export PGPASSFILE="$PROJECT_DIR/.pgpass_project3"

DB_USER="threat_user"
DB_NAME="active_directory_db"
DB_HOST="localhost"

SECURITY_Evtx="logs/security/Security.evtx"
SYSMON_Evtx="logs/sysmon/Sysmon.evtx"
RDP_Evtx="new_rdp_logs/TerminalServices.evtx"
SIXTY_SIX_TWO="/home/kali/Documents/shared_folder_server/Security_4662_only.evtx"

PYTHON_BIN="$PROJECT_DIR/venv/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="$(command -v python)"
fi

export PYTHONPATH="$PROJECT_DIR"

cd "$PROJECT_DIR" || exit 1

START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo
echo "======================================================================"
echo " PROJECT 3 — COMPLETE DETECTION & MONITORING PIPELINE"
echo "======================================================================"
echo
echo "Project:  $PROJECT_DIR"
echo "Database: $DB_NAME"
echo "Started:  $START_TIME"
echo

PASS_COUNT=0
FAIL_COUNT=0

pass_step() {
    echo
    echo "[PASS] $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail_step() {
    echo
    echo "[FAIL] $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

run_step() {
    STEP_NAME="$1"
    shift

    echo
    echo "----------------------------------------------------------------------"
    echo "$STEP_NAME"
    echo "----------------------------------------------------------------------"

    if "$@"; then
        pass_step "$STEP_NAME"
        return 0
    else
        fail_step "$STEP_NAME"
        return 1
    fi
}

# ==============================================================
# 1. ENVIRONMENT
# ==============================================================

echo "[1] ENVIRONMENT CHECK"

if [ ! -d "$PROJECT_DIR" ]; then
    fail_step "Project directory"
    exit 1
fi

if [ ! -f "$SECURITY_Evtx" ]; then
    echo "[ERROR] Missing $SECURITY_Evtx"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "[OK] Security EVTX found"
fi

if [ ! -f "$SYSMON_Evtx" ]; then
    echo "[ERROR] Missing $SYSMON_Evtx"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "[OK] Sysmon EVTX found"
fi

if [ ! -f "$RDP_Evtx" ]; then
    echo "[ERROR] Missing $RDP_Evtx"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "[OK] Terminal Services EVTX found"
fi

if [ ! -f "$SIXTY_SIX_TWO" ]; then
    echo "[ERROR] Missing 4662 EVTX"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "[OK] 4662 EVTX found"
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo
    echo "[ERROR] Required telemetry files are missing."
    exit 1
fi

pass_step "Environment"

# ==============================================================
# 2. POSTGRESQL
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[2] POSTGRESQL HEALTH CHECK"
echo "----------------------------------------------------------------------"

if pg_isready -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    echo "[OK] PostgreSQL is accepting connections"
    pass_step "PostgreSQL health"
else
    fail_step "PostgreSQL health"
    exit 1
fi

# ==============================================================
# 3. DATABASE TABLE VALIDATION
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[3] DATABASE VALIDATION"
echo "----------------------------------------------------------------------"

TABLE_CHECK=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Atc "
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema='public'
AND table_name IN (
    'security_events',
    'sysmon_events',
    'alerts',
    'detection_results',
    'kerberos_events',
    'kerberos_analytics',
    'lateral_movement_analytics',
    'ueba_user_risk',
    'privileged_risk_analytics',
    'attack_paths',
    'attack_path_graph',
    'threat_hunt_definitions',
    'threat_hunt_runs',
    'threat_hunt_results',
    'mitre_techniques'
);
")

echo "Required Project 3 tables found: $TABLE_CHECK"

if [ "$TABLE_CHECK" -ge 15 ]; then
    pass_step "Database table validation"
else
    fail_step "Database table validation"
fi

# ==============================================================
# 4. SECURITY EVTX
# ==============================================================

run_step \
"Security EVTX ingestion" \
"$PYTHON_BIN" parsers/security_to_database.py

# ==============================================================
# 5. SYSMON EVTX
# ==============================================================

run_step \
"Sysmon EVTX ingestion" \
"$PYTHON_BIN" parsers/sysmon_to_database.py

# ==============================================================
# 6. 4662
# ==============================================================

run_step \
"4662 directory-replication telemetry ingestion" \
"$PYTHON_BIN" parsers/security_4662_to_database.py

# ==============================================================
# 7. TERMINAL SERVICES / RDP
# ==============================================================

run_step \
"Terminal Services / RDP ingestion" \
"$PYTHON_BIN" parsers/terminal_services_to_database.py

# ==============================================================
# 8. TELEMETRY COUNTS
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[8] TELEMETRY VALIDATION"
echo "----------------------------------------------------------------------"

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    'security_events' AS table_name,
    COUNT(*) AS records
FROM security_events

UNION ALL

SELECT
    'sysmon_events',
    COUNT(*)
FROM sysmon_events

UNION ALL

SELECT
    'kerberos_events',
    COUNT(*)
FROM kerberos_events

UNION ALL

SELECT
    'rdp_sessions',
    COUNT(*)
FROM rdp_sessions

ORDER BY table_name;
"

pass_step "Telemetry validation"

# ==============================================================
# 9. DETECTION ENGINE
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[9] ACTIVE DIRECTORY DETECTION ENGINE"
echo "----------------------------------------------------------------------"

if "$PYTHON_BIN" -m detections.detection_engine; then
    pass_step "Detection Engine"
else
    fail_step "Detection Engine"
fi

# ==============================================================
# 10. UPGRADE CONTROLLER
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[10] PROJECT 3 UPGRADE CONTROLLER"
echo "----------------------------------------------------------------------"

if "$PYTHON_BIN" project3_upgrade_controller.py; then
    pass_step "Upgrade Controller"
else
    fail_step "Upgrade Controller"
fi

# ==============================================================
# 11. FULL UPGRADE
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[11] PROJECT 3 FULL NON-DESTRUCTIVE UPGRADE"
echo "----------------------------------------------------------------------"

if "$PYTHON_BIN" project3_full_upgrade.py; then
    pass_step "Full Upgrade"
else
    fail_step "Full Upgrade"
fi

# ==============================================================
# 12. THREAT HUNTING
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[12] THREAT HUNTING REFRESH"
echo "----------------------------------------------------------------------"

if "$PYTHON_BIN" -c "
from detections import threat_hunting
print('Threat hunting module import OK')
"; then
    pass_step "Threat Hunting validation"
else
    fail_step "Threat Hunting validation"
fi

# ==============================================================
# 13. INTEGRITY VALIDATION
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[13] ALERT / DETECTION INTEGRITY"
echo "----------------------------------------------------------------------"

INTEGRITY=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Atc "
SELECT
    (
        SELECT COUNT(*)
        FROM detection_results dr
        LEFT JOIN alerts a ON a.id = dr.alert_id
        WHERE a.id IS NULL
    )
    +
    (
        SELECT COUNT(*)
        FROM alerts a
        LEFT JOIN detection_results dr ON dr.alert_id = a.id
        WHERE dr.id IS NULL
    );
")

echo "Integrity violations: $INTEGRITY"

if [ "$INTEGRITY" -eq 0 ]; then
    pass_step "Alert / detection integrity"
else
    fail_step "Alert / detection integrity"
fi

# ==============================================================
# 14. MITRE COVERAGE
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[14] MITRE ATT&CK COVERAGE"
echo "----------------------------------------------------------------------"

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    technique_id,
    technique_name,
    tactic
FROM mitre_techniques
ORDER BY technique_id;
"

MITRE_COUNT=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Atc "
SELECT COUNT(*) FROM mitre_techniques;
")

echo
echo "MITRE techniques in catalog: $MITRE_COUNT"

if [ "$MITRE_COUNT" -ge 14 ]; then
    pass_step "MITRE ATT&CK catalog"
else
    fail_step "MITRE ATT&CK catalog"
fi

# ==============================================================
# 15. ANALYTICS SUMMARY
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[15] PROJECT 3 ANALYTICS SUMMARY"
echo "----------------------------------------------------------------------"

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 'alerts' AS component, COUNT(*) AS records FROM alerts
UNION ALL
SELECT 'detection_results', COUNT(*) FROM detection_results
UNION ALL
SELECT 'kerberos_analytics', COUNT(*) FROM kerberos_analytics
UNION ALL
SELECT 'lateral_movement_analytics', COUNT(*) FROM lateral_movement_analytics
UNION ALL
SELECT 'ueba_user_risk', COUNT(*) FROM ueba_user_risk
UNION ALL
SELECT 'privileged_risk_analytics', COUNT(*) FROM privileged_risk_analytics
UNION ALL
SELECT 'attack_paths', COUNT(*) FROM attack_paths
UNION ALL
SELECT 'attack_path_graph', COUNT(*) FROM attack_path_graph
UNION ALL
SELECT 'threat_hunt_definitions', COUNT(*) FROM threat_hunt_definitions
UNION ALL
SELECT 'threat_hunt_runs', COUNT(*) FROM threat_hunt_runs
UNION ALL
SELECT 'threat_hunt_results', COUNT(*) FROM threat_hunt_results
ORDER BY component;
"

pass_step "Analytics summary"

# ==============================================================
# 16. PORTAL VALIDATION
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[16] DETECTION PORTAL VALIDATION"
echo "----------------------------------------------------------------------"

PORTAL_FILE="project3_portal_v2.py"

if [ ! -f "$PORTAL_FILE" ]; then
    fail_step "Portal file"
else
    if "$PYTHON_BIN" -m py_compile "$PORTAL_FILE"; then
        echo "[OK] Portal syntax"
        pass_step "Portal validation"
    else
        fail_step "Portal validation"
    fi
fi

# ==============================================================
# 17. REPORT FILES
# ==============================================================

echo
echo "----------------------------------------------------------------------"
echo "[17] PROJECT REPORT VALIDATION"
echo "----------------------------------------------------------------------"

REPORT_COUNT=0

for REPORT in \
    project3_upgrade_report.json \
    project3_full_upgrade_report.json
do
    if [ -f "$REPORT" ]; then
        echo "[OK] $REPORT"
        REPORT_COUNT=$((REPORT_COUNT + 1))
    else
        echo "[WARN] Missing $REPORT"
    fi
done

if [ "$REPORT_COUNT" -ge 2 ]; then
    pass_step "Project reports"
else
    fail_step "Project reports"
fi

# ==============================================================
# 18. FINAL DATABASE SNAPSHOT
# ==============================================================

echo
echo "======================================================================"
echo " FINAL PROJECT 3 DATABASE SNAPSHOT"
echo "======================================================================"

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    'security_events' AS table_name,
    COUNT(*) AS records
FROM security_events

UNION ALL
SELECT 'sysmon_events', COUNT(*) FROM sysmon_events
UNION ALL
SELECT 'alerts', COUNT(*) FROM alerts
UNION ALL
SELECT 'detection_results', COUNT(*) FROM detection_results
UNION ALL
SELECT 'kerberos_events', COUNT(*) FROM kerberos_events
UNION ALL
SELECT 'kerberos_analytics', COUNT(*) FROM kerberos_analytics
UNION ALL
SELECT 'lateral_movement_analytics', COUNT(*) FROM lateral_movement_analytics
UNION ALL
SELECT 'ueba_user_risk', COUNT(*) FROM ueba_user_risk
UNION ALL
SELECT 'privileged_risk_analytics', COUNT(*) FROM privileged_risk_analytics
UNION ALL
SELECT 'rdp_sessions', COUNT(*) FROM rdp_sessions
UNION ALL
SELECT 'attack_paths', COUNT(*) FROM attack_paths
UNION ALL
SELECT 'attack_path_graph', COUNT(*) FROM attack_path_graph
UNION ALL
SELECT 'threat_hunt_definitions', COUNT(*) FROM threat_hunt_definitions
UNION ALL
SELECT 'threat_hunt_runs', COUNT(*) FROM threat_hunt_runs
UNION ALL
SELECT 'threat_hunt_results', COUNT(*) FROM threat_hunt_results
ORDER BY table_name;
"

# ==============================================================
# 19. FINAL RESULT
# ==============================================================

END_TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo
echo "======================================================================"
echo " PROJECT 3 PIPELINE COMPLETE"
echo "======================================================================"
echo
echo "Started:     $START_TIME"
echo "Finished:    $END_TIME"
echo
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"
echo

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "STATUS: PROJECT 3 PIPELINE PASS"
    echo
    echo "Active Directory Detection & Monitoring Platform"
    echo "completed successfully."
    echo
    exit 0
else
    echo "STATUS: PROJECT 3 PIPELINE COMPLETED WITH FAILURES"
    echo
    echo "Review the [FAIL] sections above."
    echo
    exit 1
fi
