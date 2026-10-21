"""Transactional local prediction history with idempotent batch inserts."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from .schema import METADATA

DEFAULT_DB = Path(__file__).resolve().parents[1] / 'data' / 'history.sqlite3'

def connect(path=DEFAULT_DB):
    if path == DEFAULT_DB and os.environ.get('SMART_DEFENCE_DB'):
        path = Path(os.environ['SMART_DEFENCE_DB'])
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=20)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('''CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY, batch_id TEXT NOT NULL, row_number INTEGER NOT NULL,
        created_at TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL,
        category TEXT NOT NULL, model_score REAL NOT NULL, category_score REAL NOT NULL,
        recommendation TEXT NOT NULL, model_id TEXT NOT NULL, metadata_json TEXT NOT NULL,
        UNIQUE(batch_id, row_number))''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_status ON predictions(status)')
    db.execute("""CREATE TABLE IF NOT EXISTS network_events (
        event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, mode TEXT NOT NULL,
        source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL, protocol TEXT NOT NULL,
        source_port INTEGER, destination_port INTEGER, packet_bytes INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS rule_alerts (
        alert_id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES network_events(event_id),
        timestamp TEXT NOT NULL, mode TEXT NOT NULL, source_ip TEXT NOT NULL, destination_ip TEXT,
        attack_type TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
        threshold INTEGER NOT NULL, window_seconds REAL NOT NULL,
        evidence_json TEXT NOT NULL, recommendation TEXT NOT NULL)""")
    db.execute('CREATE INDEX IF NOT EXISTS idx_rule_mode ON rule_alerts(mode,attack_type)')
    db.execute('PRAGMA foreign_keys=ON')

    db.commit()
    return db

def save_predictions(result, records, batch_id, source='CSV', path=DEFAULT_DB):
    now = datetime.now(timezone.utc).isoformat()
    values = []
    for i, (_, row) in enumerate(result.iterrows()):
        meta = {key: str(records.iloc[i][key]) for key in METADATA if key in records and pd.notna(records.iloc[i][key])}
        values.append((batch_id, i, now, source, row.status, row.category, float(row.model_score),
            float(row.category_score), row.recommendation, row.model_id, json.dumps(meta)))
    db = connect(path)
    try:
        with db:
            before = db.total_changes
            db.executemany('INSERT OR IGNORE INTO predictions (batch_id,row_number,created_at,source,status,category,model_score,category_score,recommendation,model_id,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)', values)
            return db.total_changes - before
    finally:
        db.close()

def history(status='All', category='All', search='', path=DEFAULT_DB, limit=None, offset=0):
    sql = 'SELECT * FROM predictions WHERE 1=1'
    args = []
    for column, value in [('status', status), ('category', category)]:
        if value != 'All':
            sql += f' AND {column}=?'
            args.append(value)
    if search:
        sql += ' AND (metadata_json LIKE ? OR recommendation LIKE ? OR source LIKE ?)'
        args.extend(['%' + search + '%'] * 3)
    sql += ' ORDER BY id DESC'
    if limit is not None:
        sql += ' LIMIT ? OFFSET ?'
        args.extend([int(limit), int(offset)])
    db = connect(path)
    try:
        return pd.read_sql_query(sql, db, params=args)
    finally:
        db.close()

def summary(path=DEFAULT_DB):
    db = connect(path)
    try:
        total, normal, attack = db.execute("SELECT COUNT(*), COALESCE(SUM(status='Normal'),0), COALESCE(SUM(status='Attack'),0) FROM predictions").fetchone()
        distribution = pd.read_sql_query('SELECT category, COUNT(*) AS records FROM predictions GROUP BY category', db)
        return total, normal, attack, distribution
    finally:
        db.close()


def save_network_event(record, alerts, mode, path=DEFAULT_DB):
    """Store packet metadata and its rule alerts in one transaction; retries are safe."""
    if mode not in ('Live', 'Simulation'):
        raise ValueError('Network event mode must be Live or Simulation.')
    db = connect(path)
    try:
        with db:
            db.execute('''INSERT OR IGNORE INTO network_events
                (event_id,timestamp,mode,source_ip,destination_ip,protocol,source_port,destination_port,packet_bytes)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (record['event_id'], record['timestamp'], mode, record['source_ip'], record['destination_ip'],
                 record['protocol'], record.get('source_port'), record.get('destination_port'), record['packet_bytes']))
            for alert in alerts:
                db.execute('''INSERT OR IGNORE INTO rule_alerts
                    (alert_id,event_id,timestamp,mode,source_ip,destination_ip,attack_type,severity,confidence,threshold,window_seconds,evidence_json,recommendation)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (alert['alert_id'], record['event_id'], alert['timestamp'], mode, alert['source_ip'],
                     alert.get('destination_ip'), alert['attack_type'], alert['severity'], alert['confidence'],
                     alert['threshold'], alert['window_seconds'], json.dumps(alert['evidence']), alert['recommendation']))
    finally:
        db.close()


def network_history(kind='events', mode='All', attack_type='All', search='', path=DEFAULT_DB, limit=None):
    table = 'rule_alerts' if kind == 'alerts' else 'network_events'
    sql, args = f'SELECT * FROM {table} WHERE 1=1', []
    if mode != 'All':
        sql += ' AND mode=?'; args.append(mode)
    if kind == 'alerts' and attack_type != 'All':
        sql += ' AND attack_type=?'; args.append(attack_type)
    if search:
        sql += ' AND (source_ip LIKE ? OR destination_ip LIKE ?)'
        args += ['%' + search + '%'] * 2
    sql += ' ORDER BY timestamp DESC, rowid DESC'
    if limit is not None:
        sql += ' LIMIT ?'; args.append(int(limit))
    db = connect(path)
    try:
        return pd.read_sql_query(sql, db, params=args)
    finally:
        db.close()


def network_counts(path=DEFAULT_DB):
    db = connect(path)
    try:
        return {mode: {'events': db.execute('SELECT COUNT(*) FROM network_events WHERE mode=?', (mode,)).fetchone()[0],
                       'alerts': db.execute('SELECT COUNT(*) FROM rule_alerts WHERE mode=?', (mode,)).fetchone()[0]}
                for mode in ('Live', 'Simulation')}
    finally:
        db.close()
