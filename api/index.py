"""Vercel Serverless Function entrypoint for Smart Defence Network Protection API."""
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / 'backend'
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Ensure VERCEL environment variable is recognized
os.environ.setdefault('VERCEL', '1')

# Fallback paths for SQLite databases in AWS Lambda / Vercel Serverless environment
os.environ.setdefault('SMART_DEFENCE_DB', '/tmp/history.sqlite3')
os.environ.setdefault('SMART_DEFENCE_AUTH_DB', '/tmp/auth.sqlite3')

from app import create_app

app = create_app()
