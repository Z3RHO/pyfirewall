#!/usr/bin/env python3
import sqlite3, os, time

DB_PATH = os.path.join(os.path.dirname(__file__), '../db/firewall.db')

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            protocol TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            rule TEXT,
            alerts TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            alert_type TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_event(action, protocol, src_ip, dst_ip, rule, alerts):
    try:
        conn = get_conn()
        conn.execute(
            'INSERT INTO events (timestamp, action, protocol, src_ip, dst_ip, rule, alerts) VALUES (?,?,?,?,?,?,?)',
            (time.strftime('%Y-%m-%d %H:%M:%S'), action, protocol, src_ip, dst_ip, rule, ','.join(alerts))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        pass

def save_alert(src_ip, alert_type, details):
    try:
        conn = get_conn()
        conn.execute(
            'INSERT INTO alerts (timestamp, src_ip, alert_type, details) VALUES (?,?,?,?)',
            (time.strftime('%Y-%m-%d %H:%M:%S'), src_ip, alert_type, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        pass

def get_recent_events(limit=100):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recent_alerts(limit=50):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = get_conn()
    total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    blocked = conn.execute('SELECT COUNT(*) FROM events WHERE action="BLOCK"').fetchone()[0]
    alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    conn.close()
    return {'total': total, 'blocked': blocked, 'alerts': alerts, 'allowed': total - blocked}
