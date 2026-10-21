# API contract

All routes are same-origin under `http://localhost:5000`. JSON requests and responses use UTF-8. Keep the browser's session cookie. Responses carrying private API data use `Cache-Control: no-store`.

Get `/api/session` first and retain its `csrf` value. Every POST requires the `X-CSRF-Token` header. Login rotates this token; use the replacement returned by the login response. Protected routes return 401 when not signed in; CSRF failure returns 403. Validation errors return JSON `{ "error": "..." }` with status 400. Local resource errors return 503. Uploads are limited to 100 MB per request.

| Method | Route | Input / result |
|---|---|---|
| GET | `/api/health` | Public process health |
| GET | `/api/session` | Public configured flag, signed-in username or null, CSRF token |
| POST | `/api/setup` | Public first-run only; JSON username, password, confirm_password |
| POST | `/api/login` | Public; JSON username/password; returns username and rotated csrf |
| POST | `/api/logout` | Revoke this session, stop shared capture |
| POST | `/api/password` | JSON current_password, new_password, confirm_password; revoke all sessions |
| GET | `/api/overview` | Prediction counts, model status, live/simulation counts, recent alerts |
| GET | `/api/schema` | All 41 feature names, categorical/rate/binary groups, manual defaults |
| POST | `/api/dataset` | Multipart file; preview, missing counts, numeric statistics, class counts |
| GET | `/api/model` | Full measured metrics and top feature importances |
| POST | `/api/train` | Multipart source=included/synthetic/uploads, trees=10..500; uploads require train and test files |
| POST | `/api/predict` | Multipart file, or JSON sample=true, or JSON record={41 fields}; saves complete results, previews first 500 |
| GET | `/api/sample` | Download included 25-record feature sample |
| POST | `/api/simulate` | JSON scenario=Port Scan/High Traffic Rate/Normal Traffic; synthetic events and rule alerts |
| GET | `/api/interfaces` | Available capture interfaces, or a warning and empty list |
| GET | `/api/capture` | Shared capture running flag, count, errors, latest events/alerts, evictions |
| POST | `/api/capture/start` | JSON authorized=true, interface, duration=10..120 |
| POST | `/api/capture/stop` | Stop shared capture |
| GET | `/api/history` | kind=predictions/events/alerts, page=1..; total + 100-record page |
| GET | `/api/history/export` | Same filters; complete matching CSV with formula-safe text |

History filters: predictions support `status`, `category`, `search`; events/alerts support `mode=All/Live/Simulation`, `search` by IP; alerts additionally support `attack_type=All/Port Scan/High Traffic Rate`.

Automatic live polling sends `X-Background-Poll: 1` to avoid extending the 30-minute idle timeout. This header never bypasses authentication.

The frontend uses safe text-node rendering for returned data and JSON error messages, with no external script/CDN dependencies. Content Security Policy restricts scripts/styles/connections to the same origin, and frame embedding is denied. A signed HttpOnly, SameSite=Lax cookie plus independent CSRF checks supports this local login flow. HTTPS deployment and enterprise identity are outside the delivered local setup.
