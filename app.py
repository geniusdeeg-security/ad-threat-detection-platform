"""
Project 3 — Active Directory Detection & Monitoring Platform
Detection Engineering Portal

Run:
    python app.py

Open:
    http://127.0.0.1:5000
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, render_template_string, abort
from sqlalchemy import text

from database.db_config import engine


app = Flask(__name__)


# ============================================================
# GLOBAL TEMPLATE
# ============================================================

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>{{ title }} — Project 3</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #0b1120;
            color: #e5e7eb;
        }

        a {
            color: inherit;
            text-decoration: none;
        }

        .layout {
            display: flex;
            min-height: 100vh;
        }

        .sidebar {
            width: 240px;
            background: #111827;
            border-right: 1px solid #1f2937;
            padding: 24px 16px;
            position: fixed;
            top: 0;
            bottom: 0;
            left: 0;
        }

        .brand {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 6px;
        }

        .brand-subtitle {
            color: #6b7280;
            font-size: 12px;
            margin-bottom: 30px;
        }

        .nav-title {
            color: #6b7280;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 20px 10px 8px;
        }

        .nav-link {
            display: block;
            padding: 11px 12px;
            margin: 4px 0;
            border-radius: 7px;
            color: #9ca3af;
        }

        .nav-link:hover {
            background: #1f2937;
            color: #ffffff;
        }

        .main {
            margin-left: 240px;
            width: calc(100% - 240px);
            padding: 30px;
        }

        .header {
            margin-bottom: 30px;
        }

        .header h1 {
            margin: 0 0 6px;
            font-size: 28px;
        }

        .header p {
            margin: 0;
            color: #9ca3af;
        }

        .grid {
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
        }

        .card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 20px;
        }

        .stat-number {
            font-size: 30px;
            font-weight: bold;
            margin-bottom: 6px;
        }

        .stat-label {
            color: #9ca3af;
            font-size: 13px;
        }

        .section {
            margin-top: 30px;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .section-header h2 {
            margin: 0;
            font-size: 19px;
        }

        .panel {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 10px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: #172033;
            color: #9ca3af;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .4px;
        }

        th, td {
            padding: 13px 14px;
            border-bottom: 1px solid #1f2937;
            text-align: left;
            vertical-align: top;
        }

        td {
            font-size: 13px;
        }

        tr:hover td {
            background: #151e2e;
        }

        .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .critical {
            background: #451a1a;
            color: #fca5a5;
        }

        .high {
            background: #432818;
            color: #fdba74;
        }

        .medium {
            background: #3f3512;
            color: #fde68a;
        }

        .low {
            background: #17324a;
            color: #93c5fd;
        }

        .info {
            background: #1f2937;
            color: #9ca3af;
        }

        .link {
            color: #60a5fa;
        }

        .link:hover {
            text-decoration: underline;
        }

        .button {
            display: inline-block;
            background: #2563eb;
            padding: 8px 13px;
            border-radius: 6px;
            font-size: 12px;
            color: white;
        }

        .button:hover {
            background: #1d4ed8;
        }

        .detail-grid {
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
        }

        .detail-item {
            padding: 14px;
            background: #0f172a;
            border: 1px solid #1f2937;
            border-radius: 8px;
        }

        .detail-label {
            color: #6b7280;
            font-size: 11px;
            text-transform: uppercase;
            margin-bottom: 6px;
        }

        .detail-value {
            font-size: 14px;
            word-break: break-word;
        }

        pre {
            background: #020617;
            padding: 18px;
            border-radius: 8px;
            overflow-x: auto;
            color: #cbd5e1;
            font-size: 12px;
        }

        .empty {
            padding: 30px;
            text-align: center;
            color: #6b7280;
        }

        .footer {
            margin-top: 40px;
            color: #4b5563;
            font-size: 11px;
        }

        @media (max-width: 800px) {

            .sidebar {
                position: relative;
                width: 100%;
                height: auto;
            }

            .layout {
                display: block;
            }

            .main {
                margin-left: 0;
                width: 100%;
            }

        }

    </style>

</head>

<body>

<div class="layout">

    <aside class="sidebar">

        <div class="brand">
            AD Detection Platform
        </div>

        <div class="brand-subtitle">
            Project 3 — Detection Engineering
        </div>

        <div class="nav-title">
            Monitoring
        </div>

        <a class="nav-link" href="/">
            Dashboard
        </a>

        <a class="nav-link" href="/alerts">
            Alerts
        </a>

        <a class="nav-link" href="/mitre">
            MITRE ATT&CK
        </a>

        <div class="nav-title">
            Analytics
        </div>

        <a class="nav-link" href="/api/stats">
            API Statistics
        </a>

        <div class="nav-title">
            System
        </div>

        <a class="nav-link" href="/health">
            System Health
        </a>

    </aside>


    <main class="main">

        {{ content|safe }}

        <div class="footer">
            Project 3 — Active Directory Detection & Monitoring Platform
        </div>

    </main>

</div>

</body>
</html>
"""


# ============================================================
# DATABASE HELPERS
# ============================================================

def scalar(query, parameters=None):
    with engine.connect() as conn:
        return conn.execute(
            text(query),
            parameters or {}
        ).scalar() or 0


def get_stats():

    stats = {}

    queries = {
        "alerts": "SELECT COUNT(*) FROM alerts",
        "detections": "SELECT COUNT(*) FROM detection_results",
        "security_events": "SELECT COUNT(*) FROM security_events",
        "sysmon_events": "SELECT COUNT(*) FROM sysmon_events",
        "kerberos_events": "SELECT COUNT(*) FROM kerberos_events",
        "rdp_sessions": "SELECT COUNT(*) FROM rdp_sessions",
        "attack_paths": "SELECT COUNT(*) FROM attack_paths",
        "mitre_techniques": "SELECT COUNT(*) FROM mitre_techniques",
    }

    for key, query in queries.items():

        try:
            stats[key] = scalar(query)

        except Exception:
            stats[key] = 0

    return stats


def get_severity_counts():

    query = text("""
        SELECT
            LOWER(COALESCE(severity, 'unknown')) AS severity,
            COUNT(*) AS count
        FROM alerts
        GROUP BY LOWER(COALESCE(severity, 'unknown'))
        ORDER BY count DESC;
    """)

    with engine.connect() as conn:
        return conn.execute(query).mappings().all()


def get_recent_alerts(limit=25):

    query = text("""
        SELECT
            a.id,
            a.alert_time,
            a.severity,
            a.alert_name,
            a.source_event_id,
            a.username,
            a.computer_name,
            a.description,
            dr.technique_id,
            dr.confidence_score
        FROM alerts a
        LEFT JOIN detection_results dr
            ON dr.alert_id = a.id
        ORDER BY a.id DESC
        LIMIT :limit;
    """)

    with engine.connect() as conn:
        return conn.execute(
            query,
            {"limit": limit}
        ).mappings().all()


def get_alert(alert_id):

    query = text("""
        SELECT
            a.id,
            a.alert_time,
            a.severity,
            a.alert_name,
            a.source_event_id,
            a.username,
            a.computer_name,
            a.description,
            dr.technique_id,
            dr.confidence_score,
            dr.detection_time
        FROM alerts a
        LEFT JOIN detection_results dr
            ON dr.alert_id = a.id
        WHERE a.id = :alert_id
        ORDER BY dr.id ASC
        LIMIT 1;
    """)

    with engine.connect() as conn:
        return conn.execute(
            query,
            {"alert_id": alert_id}
        ).mappings().first()


def get_source_event(source_event_id):

    if source_event_id is None:
        return None

    query = text("""
        SELECT
            id,
            event_id,
            event_time,
            computer_name,
            username,
            source_ip,
            logon_type,
            event_data
        FROM security_events
        WHERE id = :event_id
        LIMIT 1;
    """)

    with engine.connect() as conn:
        return conn.execute(
            query,
            {"event_id": source_event_id}
        ).mappings().first()


def get_mitre_coverage():

    query = text("""
        SELECT
            mt.technique_id,
            COALESCE(
                mt.technique_name,
                mt.technique_id
            ) AS technique_name,
            COALESCE(
                mt.tactic,
                'Unknown'
            ) AS tactic,
            COUNT(dr.id) AS detection_count
        FROM mitre_techniques mt
        LEFT JOIN detection_results dr
            ON dr.technique_id = mt.technique_id
        GROUP BY
            mt.technique_id,
            mt.technique_name,
            mt.tactic
        ORDER BY
            detection_count DESC,
            mt.technique_id ASC;
    """)

    with engine.connect() as conn:
        return conn.execute(query).mappings().all()


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_TEMPLATE = """
<div class="header">

    <h1>Security Operations Dashboard</h1>

    <p>
        Active Directory Detection & Monitoring Platform
    </p>

</div>


<div class="grid">

    <div class="card">
        <div class="stat-number">{{ stats.alerts }}</div>
        <div class="stat-label">Security Alerts</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.detections }}</div>
        <div class="stat-label">Detection Results</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.security_events }}</div>
        <div class="stat-label">Security Events</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.sysmon_events }}</div>
        <div class="stat-label">Sysmon Events</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.kerberos_events }}</div>
        <div class="stat-label">Kerberos Events</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.rdp_sessions }}</div>
        <div class="stat-label">RDP Sessions</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.attack_paths }}</div>
        <div class="stat-label">Attack Paths</div>
    </div>

    <div class="card">
        <div class="stat-number">{{ stats.mitre_techniques }}</div>
        <div class="stat-label">MITRE Techniques</div>
    </div>

</div>


<div class="section">

    <div class="section-header">

        <h2>Alert Severity</h2>

        <a class="button" href="/alerts">
            View All Alerts
        </a>

    </div>

    <div class="grid">

        {% for item in severity_counts %}

        <div class="card">

            <div class="stat-number">
                {{ item.count }}
            </div>

            <div class="stat-label">
                {{ item.severity }}
            </div>

        </div>

        {% endfor %}

    </div>

</div>


<div class="section">

    <div class="section-header">

        <h2>Recent Detection Activity</h2>

    </div>

    <div class="panel">

        {% if alerts %}

        <table>

            <tr>
                <th>ID</th>
                <th>Time</th>
                <th>Severity</th>
                <th>Detection</th>
                <th>User</th>
                <th>MITRE</th>
                <th>Confidence</th>
            </tr>

            {% for alert in alerts %}

            <tr>

                <td>
                    <a class="link"
                       href="/alerts/{{ alert.id }}">
                        #{{ alert.id }}
                    </a>
                </td>

                <td>
                    {{ alert.alert_time }}
                </td>

                <td>

                    <span class="severity
                        {{ alert.severity|lower }}">
                        {{ alert.severity }}
                    </span>

                </td>

                <td>
                    {{ alert.alert_name }}
                </td>

                <td>
                    {{ alert.username or '-' }}
                </td>

                <td>
                    {{ alert.technique_id or '-' }}
                </td>

                <td>
                    {{ alert.confidence_score or '-' }}
                </td>

            </tr>

            {% endfor %}

        </table>

        {% else %}

        <div class="empty">
            No alerts available.
        </div>

        {% endif %}

    </div>

</div>
"""


@app.route("/")
def dashboard():

    content = render_template_string(
        DASHBOARD_TEMPLATE,
        stats=get_stats(),
        severity_counts=get_severity_counts(),
        alerts=get_recent_alerts(10)
    )

    return render_template_string(
        BASE_HTML,
        title="Dashboard",
        content=content
    )


# ============================================================
# ALERT LIST
# ============================================================

ALERTS_TEMPLATE = """
<div class="header">

    <h1>Security Alerts</h1>

    <p>
        Detection results generated by the Project 3 detection engine.
    </p>

</div>


<div class="panel">

{% if alerts %}

<table>

    <tr>
        <th>ID</th>
        <th>Time</th>
        <th>Severity</th>
        <th>Detection</th>
        <th>User</th>
        <th>Computer</th>
        <th>MITRE</th>
        <th>Confidence</th>
        <th></th>
    </tr>

    {% for alert in alerts %}

    <tr>

        <td>#{{ alert.id }}</td>

        <td>
            {{ alert.alert_time }}
        </td>

        <td>

            <span class="severity
                {{ alert.severity|lower }}">
                {{ alert.severity }}
            </span>

        </td>

        <td>
            {{ alert.alert_name }}
        </td>

        <td>
            {{ alert.username or '-' }}
        </td>

        <td>
            {{ alert.computer_name or '-' }}
        </td>

        <td>
            {{ alert.technique_id or '-' }}
        </td>

        <td>
            {{ alert.confidence_score or '-' }}
        </td>

        <td>
            <a class="link"
               href="/alerts/{{ alert.id }}">
                Investigate
            </a>
        </td>

    </tr>

    {% endfor %}

</table>

{% else %}

<div class="empty">
    No alerts found.
</div>

{% endif %}

</div>
"""


@app.route("/alerts")
def alerts():

    content = render_template_string(
        ALERTS_TEMPLATE,
        alerts=get_recent_alerts(100)
    )

    return render_template_string(
        BASE_HTML,
        title="Alerts",
        content=content
    )


# ============================================================
# ALERT INVESTIGATION
# ============================================================

ALERT_DETAIL_TEMPLATE = """
<div class="header">

    <h1>Alert Investigation</h1>

    <p>
        Investigating alert #{{ alert.id }}
    </p>

</div>


<div class="section">

    <div class="section-header">
        <h2>Detection Summary</h2>
    </div>

    <div class="detail-grid">

        <div class="detail-item">
            <div class="detail-label">Alert ID</div>
            <div class="detail-value">
                {{ alert.id }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Detection</div>
            <div class="detail-value">
                {{ alert.alert_name }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Severity</div>
            <div class="detail-value">

                <span class="severity
                    {{ alert.severity|lower }}">
                    {{ alert.severity }}
                </span>

            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Detection Time</div>
            <div class="detail-value">
                {{ alert.alert_time }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Username</div>
            <div class="detail-value">
                {{ alert.username or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Computer</div>
            <div class="detail-value">
                {{ alert.computer_name or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">MITRE Technique</div>
            <div class="detail-value">
                {{ alert.technique_id or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Confidence</div>
            <div class="detail-value">
                {{ alert.confidence_score or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">Source Event ID</div>
            <div class="detail-value">
                {{ alert.source_event_id or '-' }}
            </div>
        </div>

    </div>

</div>


<div class="section">

    <div class="section-header">
        <h2>Detection Description</h2>
    </div>

    <div class="panel">

        <div style="padding:20px;">
            {{ alert.description or 'No description available.' }}
        </div>

    </div>

</div>


{% if source_event %}

<div class="section">

    <div class="section-header">
        <h2>Source Windows Security Event</h2>
    </div>

    <div class="detail-grid">

        <div class="detail-item">
            <div class="detail-label">
                Database Event ID
            </div>

            <div class="detail-value">
                {{ source_event.id }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Windows Event ID
            </div>

            <div class="detail-value">
                {{ source_event.event_id }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Event Time
            </div>

            <div class="detail-value">
                {{ source_event.event_time }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Username
            </div>

            <div class="detail-value">
                {{ source_event.username or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Computer
            </div>

            <div class="detail-value">
                {{ source_event.computer_name or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Source IP
            </div>

            <div class="detail-value">
                {{ source_event.source_ip or '-' }}
            </div>
        </div>

        <div class="detail-item">
            <div class="detail-label">
                Logon Type
            </div>

            <div class="detail-value">
                {{ source_event.logon_type or '-' }}
            </div>
        </div>

    </div>

</div>


<div class="section">

    <div class="section-header">
        <h2>Raw Event Data</h2>
    </div>

    <pre>{{ source_event.event_data }}</pre>

</div>

{% elif alert.source_event_id %}

<div class="section">

    <div class="panel">

        <div class="empty">
            Source event #{{ alert.source_event_id }}
            could not be found.
        </div>

    </div>

</div>

{% else %}

<div class="section">

    <div class="panel">

        <div class="empty">
            This is a behavioral/aggregated detection.
            No single source event is attached.
        </div>

    </div>

</div>

{% endif %}
"""


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):

    alert = get_alert(alert_id)

    if alert is None:
        abort(404)

    source_event = get_source_event(
        alert["source_event_id"]
    )

    content = render_template_string(
        ALERT_DETAIL_TEMPLATE,
        alert=alert,
        source_event=source_event
    )

    return render_template_string(
        BASE_HTML,
        title=f"Alert #{alert_id}",
        content=content
    )


# ============================================================
# MITRE ATT&CK
# ============================================================

MITRE_TEMPLATE = """
<div class="header">

    <h1>MITRE ATT&CK Coverage</h1>

    <p>
        Detection coverage mapped to Project 3 techniques.
    </p>

</div>


<div class="panel">

<table>

    <tr>
        <th>Technique</th>
        <th>Technique Name</th>
        <th>Tactic</th>
        <th>Detection Results</th>
        <th>Status</th>
    </tr>

    {% for item in mitre %}

    <tr>

        <td>
            <strong>{{ item.technique_id }}</strong>
        </td>

        <td>
            {{ item.technique_name }}
        </td>

        <td>
            {{ item.tactic }}
        </td>

        <td>
            {{ item.detection_count }}
        </td>

        <td>

            {% if item.detection_count > 0 %}

            <span class="severity high">
                COVERED
            </span>

            {% else %}

            <span class="severity info">
                NO CURRENT EVIDENCE
            </span>

            {% endif %}

        </td>

    </tr>

    {% endfor %}

</table>

</div>
"""


@app.route("/mitre")
def mitre():

    content = render_template_string(
        MITRE_TEMPLATE,
        mitre=get_mitre_coverage()
    )

    return render_template_string(
        BASE_HTML,
        title="MITRE ATT&CK",
        content=content
    )


# ============================================================
# API
# ============================================================

@app.route("/api/stats")
def api_stats():

    return jsonify(get_stats())


@app.route("/api/alerts")
def api_alerts():

    alerts = get_recent_alerts(100)

    return jsonify(
        [dict(alert) for alert in alerts]
    )


@app.route("/api/alerts/<int:alert_id>")
def api_alert_detail(alert_id):

    alert = get_alert(alert_id)

    if alert is None:
        return jsonify({
            "error": "Alert not found"
        }), 404

    result = {
        "alert": dict(alert),
        "source_event": None
    }

    source_event = get_source_event(
        alert["source_event_id"]
    )

    if source_event:
        result["source_event"] = dict(
            source_event
        )

    return jsonify(result)


@app.route("/api/mitre")
def api_mitre():

    return jsonify(
        [dict(item) for item in get_mitre_coverage()]
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    try:

        with engine.connect() as conn:

            conn.execute(
                text("SELECT 1")
            )

        return jsonify({
            "status": "healthy",
            "database": "connected",
            "platform": "Project 3"
        })

    except Exception as exc:

        return jsonify({
            "status": "unhealthy",
            "database": "error",
            "error": str(exc)
        }), 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return """
    <h1>404 — Not Found</h1>
    <p>The requested resource does not exist.</p>
    <p><a href="/">Return to dashboard</a></p>
    """, 404


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("PROJECT 3 — ACTIVE DIRECTORY DETECTION & MONITORING PLATFORM")
    print("DETECTION ENGINEERING PORTAL")
    print("=" * 70)
    print()
    print("Dashboard:")
    print("  http://127.0.0.1:5000")
    print()
    print("Alerts:")
    print("  http://127.0.0.1:5000/alerts")
    print()
    print("MITRE ATT&CK:")
    print("  http://127.0.0.1:5000/mitre")
    print()
    print("Health:")
    print("  http://127.0.0.1:5000/health")
    print()
    print("=" * 70)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
