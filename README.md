# AI Based Smart  Network Detection System — Frontend + Backend

This edition separates the web interface from the Python API. It retains the NSL-KDD Random Forest models, login, packet monitoring, Port Scan / High Traffic Rate rules, safe simulations, and searchable SQLite histories.

- **Frontend:** plain HTML, CSS, and JavaScript. No Node.js, npm, React build, CDN, or API key is required.
- **Backend:** Python Flask REST API, Scikit-learn, Scapy, and SQLite.
- **Database:** SQLite creates its files automatically; MySQL is not required.
- **Run:** one Python command starts the backend, which also serves the frontend at the same origin.

## File structure

```text
smart-defence-fullstack/
├── frontend/
│   ├── index.html              # Login and dashboard shell
│   ├── styles.css              # Responsive navy/cyan interface
│   └── app.js                  # Navigation, forms, API requests, tables, charts
├── backend/
│   ├── app.py                  # Flask API + frontend serving
│   ├── requirements.txt
│   ├── requirements-tested.txt
│   ├── defence/
│   │   ├── auth.py             # Salted password hashes and idle sessions
│   │   ├── capture.py          # Authorized packet monitoring
│   │   ├── rules.py            # Rolling-window detection and simulation
│   │   ├── data.py             # Schema validation and original NSL-KDD parsing
│   │   ├── schema.py           # 41 features and attack mapping
│   │   ├── model.py            # Training, evaluation, prediction, model integrity
│   │   └── storage.py          # Predictions, network events, and rule alerts
│   ├── data/                   # NSL-KDD files and source/checksum manifest
│   ├── models/                 # Included trained model and evaluation metadata
│   ├── samples/                # Input samples and synthetic fixtures
│   ├── scripts/                # Train, predict, prepare data, reset password
│   └── tests/                  # Core and Flask API checks
├── docs/                       # Measured results, API guide, verification
├── start_windows.bat
└── README.md
```

## Run on your Windows laptop

1. Install **Python 3.12** with **Add Python to PATH** enabled.
2. Download and extract the entire ZIP using **Extract All**. Keep both `frontend` and `backend` inside `smart-defence-fullstack`.
3. Open the extracted `backend` folder. Click the File Explorer address bar, type `cmd`, and press Enter.
4. Run these commands one at a time:

```bat
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements-tested.txt
.venv\Scripts\python.exe app.py
```

5. Open **http://localhost:5000** in Chrome, Edge, or Firefox.
6. On first launch, create the administrator account. Choose a 3–32 character username using letters, digits, dots, underscores, or hyphens and a password of 12–256 characters. Then sign in. There is no default account or password.
7. Keep the terminal open while using the project. Stop it with **Ctrl+C**.

After installation, you can double-click `start_windows.bat` in the main project folder.

**Do not open `frontend/index.html` directly, and do not run VS Code Live Server for this edition.** Flask serves the frontend and API together, so login cookies and requests work without CORS configuration. Run `backend/app.py`, not the old Streamlit command.

If `py -3.12` is not recognized, install Python 3.12 or check `py --list`. If port 5000 is already occupied, stop the application using that port before starting this project.

### macOS / Linux

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-tested.txt
.venv/bin/python app.py
```

Open http://localhost:5000.

## Dashboard pages

- **Overview:** saved ML prediction counts, measured model accuracy, live/simulation event and alert counts, and recent alerts.
- **Dataset Analysis:** upload original comma-delimited NSL-KDD text or a named CSV to inspect records, missing values, numeric statistics, and class distribution.
- **Model Training:** train on the included datasets, upload your own compatible train/test files, or try explicitly synthetic fixtures. Separate binary and category models are trained using training-only preprocessing. Training is synchronous: wait for the request to complete. Full training can take a few minutes on a laptop.
- **Traffic Prediction:** analyze the included 25-record NSL-KDD sample, upload a compatible CSV, or enter all 41 fields manually. Results are stored automatically. Up to 500 result rows are previewed; export complete saved results from Alert History.
- **Live Monitoring:** confirm network authorization, select an available interface, and start/stop passive capture. Capture automatically expires within the chosen 10–120 seconds. Status refreshes every two seconds without extending the login idle timer.
- **Simulation Mode:** choose Port Scan, High Traffic Rate, or Normal Traffic. Synthetic metadata passes through the same rule engine, without transmitting packets. Events and alerts are labeled Simulation.
- **Network Events:** filter captured/simulated metadata by mode and addresses, paginate, and export all matching rows.
- **Alert History:** inspect either rule alerts or ML predictions, filter them, and export CSV.
- **Account:** change the administrator password. All sessions are revoked; sign in again.

### Try it immediately

1. Sign in, then open **Simulation Mode → Port Scan → Run simulation**: eight events and one rule alert should appear.
2. Run **High Traffic Rate**: 100 events and one rule alert.
3. Run **Normal Traffic**: 20 events and no rule alerts.
4. Check **Network Events** and **Alert History → Rule alerts**; use mode Simulation.
5. Open **Traffic Prediction**, use **Included NSL-KDD sample**, and select **Analyze records**. All 25 prediction events are saved.

## Detection logic and limitations

| Rule | Source-IP trigger | Rolling window | Configured severity |
|---|---|---|---|
| Port Scan | At least 8 different destination port numbers | 10 seconds | High |
| High Traffic Rate | At least 100 IP packets | 5 seconds | Medium |

Windows include the exact left boundary. Ports are grouped by source across destination hosts; repeated contacts to one port do not increase the unique-port count. Packets without transport ports still count toward packet rate. Live rules use monotonic processing-observation time; UTC capture timestamps are displayed and saved. Under load, processing delay or packet loss can affect coverage.

Alerts occur on threshold crossings, then rearm when the condition drops below threshold. Confidence is explicitly labeled **Threshold matched (rule-based; no probability)**. It is not a fabricated AI score or proof of an attack. State is bounded to 4,096 active sources; evictions are reported. Packet-rate evidence reports **at least 100** because the latest 100 packet times suffice to test the threshold. The latest 1,000 packet/alert summaries remain in memory; metadata and alerts are also persisted.

The Random Forest model is separate. It classifies compatible NSL-KDD connection records, not individual live packets. A complete live NSL-KDD feature extractor is not implemented. All 41 features are retained; numeric median imputation and categorical one-hot vocabulary are fitted on training data only. Unknown feature categories are accepted with a warning; unknown attack labels are rejected. Original headerless 41/42/43-column records and named CSVs are supported. Invalid schema/data is rejected rather than silently padded.

Binary status gates the displayed category: Normal status shows Normal; Attack status chooses the category model's highest scoring attack class. Model scores are uncalibrated estimates. Independent category and displayed workflow-category evaluations are both recorded. The original-data measured binary accuracy is **77.16%** on the 22,544-record held-out file; category-specific weaknesses and full matrices are in `docs/MEASURED_RESULTS.md`. These historical benchmark results do not establish performance on modern production networks.

No automatic blocking, active attack generation, phishing identification, malware classification, or encryption verification is claimed.

## Login and stored data

- First-run account setup creates one administrator only, with no public registration after setup.
- Passwords use PBKDF2-HMAC-SHA256, 600,000 iterations, fresh 16-byte salt, and constant-time hash comparison.
- Five incorrect login attempts lock the account for 60 seconds; this state is persisted across browser sessions.
- Idle sessions expire after 30 minutes. Normal dashboard API interactions renew the timer; automatic live polling does not. Logout and password changes revoke sessions.
- Flask uses an HttpOnly, SameSite=Lax, signed session cookie containing an opaque random authentication token. The backend validates its SHA-256 digest against the session database. A CSRF token is required for every state-changing API call, including login/setup. Tokens are not placed in URLs. Local HTTP uses cookies without Secure; this app binds to localhost and is not an internet deployment setup.
- `backend/data/auth.sqlite3` holds password hashes, lockout state, and hashed authentication tokens.
- `backend/data/history.sqlite3` holds prediction history, packet metadata, and rule alerts. Payloads are never retained.
- `backend/data/flask_secret.key` is generated locally on first run to sign cookies; it is not included in this download. Keep it private. Changing it signs existing browsers out.
- The package contains no credential database, active sessions, private signing key, or default password. There is no MySQL setup or cloud account requirement.
- This is one local administrator workspace. Captures are shared within this backend instance; logout stops the current capture. Capture also auto-stops within 120 seconds if a browser closes or disconnects.

### Forgotten password

Stop the backend, open a terminal in `backend`, and run:

```bat
.venv\Scripts\python.exe -m scripts.reset_admin
```

Enter the administrator username and new password at the hidden prompts. All sessions are revoked. Restart `app.py` and sign in again. This trusted local recovery command is not exposed as an unauthenticated API.

## CLI utilities and tests

Run from the `backend` folder; substitute your virtual environment's Python if needed:

```bash
python -m scripts.download_data
python -m scripts.prepare_data "data/KDDTrain+.txt" data/train_named.csv
python -m scripts.train --train "data/KDDTrain+.txt" --test "data/KDDTest+.txt" --trees 150
python -m scripts.predict samples/nsl_kdd_prediction_sample.csv --output predictions.csv
python -m scripts.init_db
python -m pytest -q
```

Compatible dependency ranges are in `requirements.txt`; tested direct versions are in `requirements-tested.txt`. The bundled model requires its exact scikit-learn version or retraining. Joblib models must come from a trusted source; an integrity hash detects accidental corruption, not malicious replacements. Core CLI tools run locally and are not sandboxed by the dashboard login.

## Updating from the Streamlit edition

This is a separate full-stack copy. Keep the original ZIP if you still want Streamlit. To carry over your own history/account, stop both applications and copy your existing `data/history.sqlite3` and `data/auth.sqlite3` into this edition's `backend/data/` before starting it. Make a backup first. No migration is needed for their current schemas. Browser sessions do not transfer; sign in again. Do not copy transient `-wal`/`-shm` files from a running application.

## Dataset attribution

ISCX NSL-KDD (2009), University of New Brunswick / Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/nsl.html

The official page permits redistribution with attribution and currently no longer hosts the download. Included original-format files were retrieved from the public mirror https://github.com/defcom17/NSL_KDD. Exact URLs, sizes, counts, and SHA-256 values are in `backend/data/provenance.json`. Mirror hashes pin retrieved bytes, not an independent official signature.

Required paper citation: M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, **“A Detailed Analysis of the KDD CUP 99 Data Set,”** IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA), 2009. DOI: 10.1109/CISDA.2009.5356528.

Primary implementation references: https://flask.palletsprojects.com/en/stable/ ; https://scikit-learn.org/stable/modules/compose.html ; https://docs.python.org/3/library/hashlib.html ; https://scapy.readthedocs.io/en/latest/usage.html.
