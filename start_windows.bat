@echo off
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  echo Follow README.md to create the backend virtual environment and install requirements first.
  pause
  exit /b 1
)
echo Open http://localhost:5000 after the server starts.
".venv\Scripts\python.exe" app.py
pause
