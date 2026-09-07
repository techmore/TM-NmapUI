# TM-NmapUI macOS known-good release

This release is preserved from `TM-NmapUI.zip` as a standalone Node/Express build.

- Source archive: `TM-NmapUI.zip`
- Embedded source commit: `e472424` (`Merge express-dev into main`)
- Runtime: Node.js + Express + Socket.IO
- Includes: Web UI, Nmap scanning, live updates, HTML/PDF reports, and Google Drive uploads
- macOS setup: run `./install.sh`, then `npm start`; open `http://localhost:9000`

The archive is intentionally kept byte-for-byte intact. It is a rollback/reference release and is not merged into the current Flask application.
