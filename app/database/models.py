"""SQLite persistence for scan history.  Every query is parameterized."""
import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    domain          TEXT    NOT NULL,
    scanned_at      TEXT    NOT NULL,
    risk_score      INTEGER NOT NULL,
    level           TEXT    NOT NULL,
    classification  TEXT    NOT NULL,
    verdict         TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    report_json     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_id_desc ON scans (id DESC);
"""

SUMMARY_COLUMNS = (
    "id, url, domain, scanned_at, risk_score, level, classification, verdict, status"
)


@contextmanager
def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path):
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def save_scan(path, report, max_history=500):
    risk = report["risk"]
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, domain, scanned_at, risk_score, level, classification,"
            " verdict, status, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report["input_url"],
                report["domain"],
                report["scanned_at"],
                int(risk["score"]),
                risk["level"],
                risk["classification"],
                risk["verdict"],
                risk["status"],
                json.dumps(report, ensure_ascii=False),
            ),
        )
        scan_id = cur.lastrowid
        conn.execute(
            "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
            (int(max_history),),
        )
    return scan_id


def list_scans(path, limit=50):
    limit = max(1, min(int(limit), 500))
    with connect(path) as conn:
        rows = conn.execute(
            f"SELECT {SUMMARY_COLUMNS} FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(path, scan_id):
    with connect(path) as conn:
        row = conn.execute(
            f"SELECT {SUMMARY_COLUMNS}, report_json FROM scans WHERE id = ?", (int(scan_id),)
        ).fetchone()
    if row is None:
        return None
    data = dict(row)
    report = json.loads(data.pop("report_json"))
    return {"id": data["id"], "report": report}


def delete_scan(path, scan_id):
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
        return cur.rowcount > 0


def clear_scans(path):
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM scans")
        return cur.rowcount


def get_stats(path):
    with connect(path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN verdict = 'confirmed_malicious' THEN 1 ELSE 0 END) AS confirmed,"
            " SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,"
            " SUM(CASE WHEN verdict = 'no_known_threats' THEN 1 ELSE 0 END) AS no_known,"
            " SUM(CASE WHEN verdict = 'inconclusive' THEN 1 ELSE 0 END) AS inconclusive,"
            " SUM(CASE WHEN level IN ('high', 'critical') THEN 1 ELSE 0 END) AS high_risk,"
            " AVG(risk_score) AS avg_score FROM scans"
        ).fetchone()
    return {
        "total": row["total"] or 0,
        "confirmed_malicious": row["confirmed"] or 0,
        "suspicious": row["suspicious"] or 0,
        "no_known_threats": row["no_known"] or 0,
        "inconclusive": row["inconclusive"] or 0,
        "high_risk": row["high_risk"] or 0,
        "average_score": round(row["avg_score"], 1) if row["avg_score"] is not None else None,
    }
