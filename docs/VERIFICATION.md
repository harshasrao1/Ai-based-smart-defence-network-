# Verification — separate frontend/backend edition

## Backend

`python -m pytest -q` from `backend/`: **43 passed, 1 skipped**.

The skipped Scapy packet-parsing test is due to the build host denying network-interface enumeration. Actual live packet capture must be verified on an authorized laptop interface with its capture backend/permissions installed. Interface-unavailable responses and simulation functionality are checked without privileged capture.

Checks cover original 41/42/43-column NSL-KDD parsing, validation, training-only preprocessing, unknown categories and attack labels, missing values, model reloading and corruption checks, prediction persistence, SQL-safe filtering, source-isolated rule thresholds, exact 5/10-second boundaries, duplicate-alert suppression, rearming, bounded state, authentication, password changes, session revocation, and local recovery.

Flask API tests cover login gates, static frontend serving, disallowed file paths, CSRF rejection, setup/login/logout, measured model reports, real-sample/manual/file predictions, dataset analysis, temporary-directory training, all three simulations, mode-separated histories, exports, and capture authorization. Test databases, accounts, and training output are isolated in temporary folders. The bundled model is not replaced by tests.

## Frontend integration

`node --check frontend/app.js` passes.

A separate JavaScript DOM integration run used JSDOM against a live local Flask server, with a cookie-aware fetch adapter and isolated authentication/history databases. It exercised first setup, sign-in, all nine navigation pages, the port-scan simulation, persisted event and alert history, all 25 included NSL-KDD sample predictions, model reports, password changes, sign-in with the new password, and logout. The run completed with no JavaScript DOM errors.

Canvas rendering was stubbed in this DOM test; it is not a visual screenshot or a full real-browser layout review. No headless browser executable was available. Native multipart file uploads are covered by backend API tests; the DOM integration used the included sample input.

## Distribution

The complete NSL-KDD data/model and measured results are retained. Binary held-out accuracy remains **77.16%**; complete independent and workflow category metrics are in `MEASURED_RESULTS.md` and `evaluation.json`.

The ZIP excludes virtual environments, Python caches, test caches, credential/history databases, session files, and the local Flask signing key. It includes no default administrator credentials. Runtime databases/key are created on the user's laptop. Source files are split into `frontend/` and `backend/`, with no frontend build tool or cloud dependency.
