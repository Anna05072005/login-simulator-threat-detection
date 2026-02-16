
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime

def run_sql_file(conn: sqlite3.Connection, path: str) -> None:
    sql = Path(path).read_text(encoding="utf-8")
    conn.executescript(sql)

def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)
    ).fetchone() is not None

def main():
    ap = argparse.ArgumentParser(description="Run SQL detections and write alerts.")
    ap.add_argument("--db", default="data/siem.db")
    ap.add_argument("--schema", default="schema.sql")
    ap.add_argument("--detections", default="detections.sql")
    ap.add_argument("--init-schema", action="store_true")
    ap.add_argument("--show", type=int, default=25)
    args = ap.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    if args.init_schema:
        run_sql_file(conn, args.schema)
        conn.commit()

    if not table_exists(conn, "alerts"):
        raise RuntimeError("alerts table not found. Run with --init-schema first.")

    before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # Run SQL-based detection rules (INSERT INTO alerts ... SELECT ...)
    run_sql_file(conn, args.detections)
    conn.commit()

    after = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print("=" * 60)
    print(f"Detections run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"DB: {args.db}")
    print(f"New alerts inserted: {after - before}")
    print(f"Total alerts: {after}")
    print("=" * 60)

    rows = conn.execute(
        """
        SELECT ts, severity, alert_type, user_id, ip, details
        FROM alerts
        ORDER BY alert_id DESC
        LIMIT ?
        """,
        (args.show,)
    ).fetchall()

    for r in rows:
        print(dict(r))

    conn.close()

if __name__ == "__main__":
    main()
