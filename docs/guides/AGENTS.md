# Guide maintenance

The root `AGENTS.md` and `docs/notes/PROJECT_STATUS.md` describe the current
product and repository workflows. Keep this directory's setup, build and
release guides consistent with those files and the commands that exist in the
repository.

- The maintained application is Flask (`app.py` and `nmapui/`).
- The supported macOS bundle uses root `build.sh`; PyInstaller and `deploy.sh`
  are historical references. macOS and Ubuntu are scanner-host targets.
  Ubuntu's installer and systemd unit are implemented as a candidate and have
  disposable-VM lifecycle validation; physical-interface scans, an unattended
  soak and release remain outstanding. Hosted CI passed all four jobs on
  `17fa8ad1`; later code revisions require fresh checks.
- Container deployment is retired. Preserve the scanner host's direct network
  access requirement.
- Python 3.11 is the CI baseline; use `.venv/bin/python -m pytest -q` for the
  full suite. Browser and packaged checks have explicit environment gates.
- Do not document live scanner or service-install commands as harmless checks.
- Keep credentials, real scan data and generated app bundles out of examples and
  version control.
