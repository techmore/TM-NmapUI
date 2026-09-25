# Repository Layout

The maintained product is a shared Flask application targeting macOS and Ubuntu
scanner hosts, with a cross-platform browser UI and an optional macOS menu-bar
launcher. Ubuntu service packaging is still in progress.

## Current code

- `/` — `app.py`, `start.sh`, `install.sh`, `build.sh`, requirements and version
- `nmapui/` — scanning, reporting, scheduling, authentication and runtime state
- `nmapui/handlers/` — HTTP and Socket.IO route registration
- `templates/`, `static/` — the shared web interface
- `packaging/macos/` — Swift launcher, LaunchDaemon installer and scanner helper
- Ubuntu installer and systemd service — tracked in issue #241; not yet shipped
- `tests/` — unit, contract, browser and packaged-app checks
- `docs/guides/`, `docs/notes/`, `docs/audits/` — setup, product status and review

## Historical references

- `packaging/pyinstaller/` and `deploy.sh` describe a retired packaging path.
- `server.js`, root `index.html`, `static/js/`, `package.json`, `Dockerfile` and
  `docker-compose.yml` are legacy Node runtime references. Containers are not a
  supported deployment because the scanner needs direct host networking.
- Keep the known-good Mac alpha archive and branch available as rollback
  references.

Runtime state (`data/`, SQLite files, logs, local customer configuration,
generated reports and built `.app` bundles) stays out of version control.
