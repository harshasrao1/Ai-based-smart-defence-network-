import sqlite3
import pytest
from defence.auth import (AuthError, hash_password, verify_password, setup_admin, is_configured,
                          login, session_user, logout, change_password, reset_password, IDLE_SECONDS)

PASSWORD = 'Test-only-Long-Passphrase-123'
NEW_PASSWORD = 'Replacement-Long-Passphrase-456'

@pytest.fixture
def database(tmp_path):
    path = tmp_path/'auth.sqlite3'
    setup_admin('admin', PASSWORD, path)
    return path


def test_hash_salts_and_invalid_passwords():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second
    assert PASSWORD not in first
    assert verify_password(PASSWORD, first)
    assert not verify_password('wrong', first)
    assert not verify_password(PASSWORD, 'broken')
    with pytest.raises(AuthError): hash_password('short')


def test_first_setup_once_and_validation(tmp_path):
    path = tmp_path/'first.sqlite3'
    assert not is_configured(path)
    with pytest.raises(AuthError): setup_admin('bad user', PASSWORD, path)
    setup_admin('ADMIN', PASSWORD, path)
    assert is_configured(path)
    with pytest.raises(AuthError): setup_admin('other', PASSWORD, path)
    assert session_user(login('admin', PASSWORD, path, now=0), path, now=1) == 'admin'


def test_session_expiry_refresh_and_logout(database):
    token = login('admin', PASSWORD, database, now=100)
    assert session_user('invented', database, now=100) is None
    assert session_user(token, database, now=101, touch=True) == 'admin'
    assert session_user(token, database, now=100 + IDLE_SECONDS, touch=False) == 'admin'
    assert session_user(token, database, now=101 + IDLE_SECONDS, touch=False) is None
    token = login('admin', PASSWORD, database, now=10000)
    logout(token, database)
    assert session_user(token, database, now=10001) is None


def test_invalid_logins_lock_and_recover(database):
    for _ in range(5):
        with pytest.raises(AuthError): login('admin', 'wrong', database, now=100)
    with pytest.raises(AuthError, match='temporarily locked'):
        login('admin', PASSWORD, database, now=159)
    token = login('admin', PASSWORD, database, now=160)
    assert session_user(token, database, now=161) == 'admin'
    with pytest.raises(AuthError): login('not_admin', PASSWORD, database, now=162)


def test_no_password_or_raw_session_token_stored(database):
    token = login('admin', PASSWORD, database, now=1)
    with sqlite3.connect(database) as db:
        password_hash = db.execute('SELECT password_hash FROM admin').fetchone()[0]
        token_hash = db.execute('SELECT token_hash FROM auth_sessions').fetchone()[0]
    assert password_hash.startswith('pbkdf2_sha256$600000$')
    assert PASSWORD not in password_hash
    assert token_hash != token
    assert len(token_hash) == 64


def test_password_change_requires_current_and_revokes_all_sessions(database):
    first = login('admin', PASSWORD, database, now=10)
    second = login('admin', PASSWORD, database, now=10)
    with pytest.raises(AuthError): change_password(first, 'wrong', NEW_PASSWORD, database, now=11)
    assert session_user(first, database, now=12) == 'admin'
    change_password(first, PASSWORD, NEW_PASSWORD, database, now=13)
    assert session_user(first, database, now=14) is None
    assert session_user(second, database, now=14) is None
    with pytest.raises(AuthError): login('admin', PASSWORD, database, now=15)
    assert login('admin', NEW_PASSWORD, database, now=16)


def test_local_recovery_revokes_sessions(database):
    token = login('admin', PASSWORD, database, now=1)
    with pytest.raises(AuthError): reset_password('other', NEW_PASSWORD, database)
    reset_password('admin', NEW_PASSWORD, database)
    assert session_user(token, database, now=2) is None
    assert login('admin', NEW_PASSWORD, database, now=3)
