# elementary OS

The native elementary OS app moved to its own repository:
<https://github.com/techmore/TM-NmapUI-elementary>.

It contains the Granite/GTK 4 **Network Scanner** window, the Wingpanel indicator, the
`nmapui-summary` helper, the per-user `nmapui.service` unit (Gunicorn, loopback only) and the
installers. Its `scripts/install-backend.sh` clones this repository's `main` branch and runs the
Flask engine as the user service that the app and indicator talk to.

Nothing in this directory is built or installed any more; it stays as a pointer so older links
and notes still resolve.
