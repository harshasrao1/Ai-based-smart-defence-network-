# Frontend

- `index.html`: login/setup screen and dashboard shell.
- `styles.css`: responsive interface and page styling.
- `app.js`: plain JavaScript navigation, API calls, forms, tables, chart rendering, polling, and exports.

The frontend uses relative `/api/...` requests. Flask serves these files and the API from http://localhost:5000. Do not open index.html directly or run an independent Live Server. No Node.js/npm installation is required to run or edit this frontend. Change the frontend files, then reload the browser.

Backend API details are in `../docs/API.md`. Full installation steps are in `../README.md`.
