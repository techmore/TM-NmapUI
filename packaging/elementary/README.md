# Elementary OS desktop candidate

This GTK 4 / WebKitGTK 6 shell retains the Flask UI, Socket.IO, persistent browser
sign-in, OAuth popup windows and report downloads. It opens the loopback backend
at `http://127.0.0.1:9000` and does not implement another scanning engine.

Install system dependencies from the Ubuntu guide, plus `python3-gi`,
`gir1.2-gtk-4.0` and `gir1.2-webkit-6.0`. Create `.venv` with the system Python,
install `requirements.txt`, then run:

```sh
.venv/bin/python -m playwright install chromium
bash packaging/elementary/install-desktop.sh
```

The launcher appears as **TM NmapUI**. The installer enables a loopback-only
**unprivileged** user service, `nmapui-local.service`; data and logs are private
under `~/.local/share/nmapui` and `~/.local/state/nmapui`. Remote fingerprint,
update and Vulners requests are disabled initially. Scans are user-initiated.
Root-only scan techniques are unavailable in this mode; the backend reports its
unprivileged fallback. Do not run this and the root Ubuntu service on port 9000
simultaneously. Stop/disable the user service before choosing the separately
reviewed protected Ubuntu service installer.

Validated on elementary OS ARM64: backend readiness with physical interface `wld0`,
scanner dependency checks, native desktop startup, and existing Linux service tests
(15 passed / 5 skipped). These checks did not scan the LAN, validate privileged
scanning or establish unattended production readiness.
