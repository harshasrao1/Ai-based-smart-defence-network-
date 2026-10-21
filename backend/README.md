# Backend

Open a terminal here, create a Python 3.12 environment, install `requirements-tested.txt`, and run `python app.py` using that environment. The server binds to `127.0.0.1:5000` and serves the sibling `frontend/` folder and the Flask API. Keep both folders in their original positions.

The Flask development server is intended for this local academic project; debug mode is disabled. The shared capture monitor belongs to this one local backend process. Rules, ML pipelines, and SQLite persistence are modular under `defence/`.

From this folder, run `python -m pytest -q` for checks. Tests isolate authentication/history state in temporary databases; the training endpoint test writes models to a temporary directory and leaves the included model active.

Full instructions and limitations are in `../README.md`; API routes are documented in `../docs/API.md`.
