"""Local single-admin authentication with salted password hashes and idle sessions."""
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

ITERATIONS = 600_000
IDLE_SECONDS = 30 * 60
LOCK_SECONDS = 60
MAX_FAILURES = 5
DEFAULT_AUTH_DB = Path(__file__).resolve().parents[1] / 'data' / 'auth.sqlite3'

class AuthError(ValueError):
    pass


def _connect(path=None):
    target = Path(path or os.environ.get('SMART_DEFENCE_AUTH_DB') or DEFAULT_AUTH_DB)
    target.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(target, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('''CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY CHECK(id=1), username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until REAL NOT NULL DEFAULT 0)''')
    db.execute('''CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at REAL NOT NULL)''')
    db.commit()
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return db


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise AuthError('Choose a password containing 12–256 characters.')


def hash_password(password):
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}'


def verify_password(password, encoded):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        algorithm, rounds, salt, expected = encoded.split('$')
        if algorithm != 'pbkdf2_sha256' or int(rounds) != ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def is_configured(path=None):
    db = _connect(path)
    try:
        return db.execute('SELECT 1 FROM admin WHERE id=1').fetchone() is not None
    finally:
        db.close()


def setup_admin(username, password, path=None):
    username = username.strip().lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,32}', username):
        raise AuthError('Username must be 3–32 letters, digits, dots, underscores or hyphens.')
    encoded = hash_password(password)
    db = _connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM admin WHERE id=1').fetchone():
            raise AuthError('An administrator already exists. Sign in instead.')
        db.execute('INSERT INTO admin(id,username,password_hash) VALUES (1,?,?)', (username, encoded))
        db.commit()
    finally:
        db.close()


def _token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def login(username, password, path=None, now=None):
    now = time.time() if now is None else now
    db = _connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        user = db.execute('SELECT * FROM admin WHERE id=1').fetchone()
        if user is None:
            raise AuthError('Create the administrator account first.')
        if user['locked_until'] > now:
            raise AuthError('Sign-in is temporarily locked. Wait one minute and try again.')
        password_ok = verify_password(password, user['password_hash'])
        if username.strip().lower() != user['username'] or not password_ok:
            failures = user['failed_attempts'] + 1 if user['locked_until'] == 0 else 1
            locked_until = now + LOCK_SECONDS if failures >= MAX_FAILURES else 0
            db.execute('UPDATE admin SET failed_attempts=?,locked_until=? WHERE id=1', (failures, locked_until))
            db.commit()
            raise AuthError('Invalid username or password.' if not locked_until else 'Too many failed attempts. Wait one minute and try again.')
        db.execute('UPDATE admin SET failed_attempts=0,locked_until=0 WHERE id=1')
        db.execute('DELETE FROM auth_sessions WHERE expires_at<=?', (now,))
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO auth_sessions VALUES (?,?,?)', (_token_hash(token), user['username'], now + IDLE_SECONDS))
        db.commit()
        return token
    finally:
        db.close()


def session_user(token, path=None, now=None, touch=True):
    if not isinstance(token, str) or not 20 <= len(token) <= 128:
        return None
    now = time.time() if now is None else now
    db = _connect(path)
    try:
        with db:
            db.execute('DELETE FROM auth_sessions WHERE expires_at<=?', (now,))
            row = db.execute('SELECT username FROM auth_sessions WHERE token_hash=?', (_token_hash(token),)).fetchone()
            if row is None:
                return None
            if touch:
                db.execute('UPDATE auth_sessions SET expires_at=? WHERE token_hash=?', (now + IDLE_SECONDS, _token_hash(token)))
            return row['username']
    finally:
        db.close()


def logout(token, path=None):
    if not isinstance(token, str):
        return
    db = _connect(path)
    try:
        with db:
            db.execute('DELETE FROM auth_sessions WHERE token_hash=?', (_token_hash(token),))
    finally:
        db.close()


def change_password(token, current_password, new_password, path=None, now=None):
    now = time.time() if now is None else now
    validate_password(new_password)
    db = _connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        session = db.execute('SELECT username FROM auth_sessions WHERE token_hash=? AND expires_at>?', (_token_hash(token), now)).fetchone()
        user = db.execute('SELECT * FROM admin WHERE id=1').fetchone()
        if session is None or user is None or not verify_password(current_password, user['password_hash']):
            raise AuthError('Session expired or current password is incorrect.')
        db.execute('UPDATE admin SET password_hash=?,failed_attempts=0,locked_until=0 WHERE id=1', (hash_password(new_password),))
        db.execute('DELETE FROM auth_sessions')
        db.commit()
    finally:
        db.close()


def reset_password(username, new_password, path=None):
    """Trusted local CLI recovery only; no web reset endpoint."""
    encoded = hash_password(new_password)
    db = _connect(path)
    try:
        with db:
            row = db.execute('SELECT username FROM admin WHERE id=1').fetchone()
            if row is None or row['username'] != username.strip().lower():
                raise AuthError('Administrator username not found.')
            db.execute('UPDATE admin SET password_hash=?,failed_attempts=0,locked_until=0 WHERE id=1', (encoded,))
            db.execute('DELETE FROM auth_sessions')
    finally:
        db.close()
