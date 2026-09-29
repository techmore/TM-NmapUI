import os
from pathlib import Path
import shutil
import tempfile
from typing import Optional


BASE_DIR = Path(__file__).resolve().parents[1]


def _privileged_asset(name: str, fallback: Path) -> Path:
    """Prefer the root-owned asset copy used by the privileged scanner helper.

    The helper refuses `--script`/`--stylesheet` paths that are not inside the
    root-owned asset directory, so a writable checkout cannot smuggle executable
    Lua into a root-run nmap. Falls back to the checkout for development.
    """
    asset_dir = str(os.environ.get("NMAPUI_PRIVILEGED_ASSETS", "") or "").strip()
    if asset_dir:
        candidate = Path(asset_dir).expanduser() / name
        if candidate.exists():
            return candidate
    return fallback


VULNERS_SCRIPT = _privileged_asset(
    "vulners.nse", BASE_DIR / "nmap-vulners" / "vulners.nse"
)
XSL_STYLESHEET = _privileged_asset("nmap-modern.xsl", BASE_DIR / "nmap-modern.xsl")
XSL_STYLESHEET_PDF = _privileged_asset(
    "nmap-pdf-olive-legacy.xsl", BASE_DIR / "nmap-pdf-olive-legacy.xsl"
)


def _resolve_data_dir() -> Path:
    override = str(os.environ.get("NMAPUI_DATA_DIR", "") or "").strip()
    if override:
        return Path(override).expanduser()
    return BASE_DIR / "data"


DATA_DIR = _resolve_data_dir()
SCANS_DIR = DATA_DIR / "scans"
VERSION_FILE = BASE_DIR / "VERSION"
CURRENT_ASSIGNMENT_FILE = DATA_DIR / "current_assignment.json"
# Schedule state belongs in the data dir.  It used to live in BASE_DIR, which is
# the app bundle in packaged builds: enabling auto-scan then silently failed to
# persist (or was wiped by the next app update), so an appliance lost its
# schedule.  The legacy location is still read once for migration.
AUTO_SCAN_CONFIG_FILE = DATA_DIR / "auto_scan_config.json"
LEGACY_AUTO_SCAN_CONFIG_FILE = BASE_DIR / "auto_scan_config.json"
AUTO_SCAN_CONFIG_EXAMPLE_FILE = BASE_DIR / "config" / "auto_scan_config.example.json"
AUTO_SCAN_SCHEDULER_LOCK_FILE = DATA_DIR / "auto_scan_scheduler.lock"
SETTINGS_FILE = DATA_DIR / "settings.json"
SESSION_SECRET_FILE = DATA_DIR / "session.key"
RUNTIME_DB_FILE = DATA_DIR / "runtime.sqlite3"
CUSTOMER_CONFIG_FILE = DATA_DIR / "customers.yaml"
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"
GOOGLE_DRIVE_CREDENTIALS_FILE = DATA_DIR / "google_drive_credentials.json"
GOOGLE_DRIVE_TOKEN_FILE = DATA_DIR / "google_drive_tokens.json"
GOOGLE_DRIVE_TOKEN_KEY_FILE = DATA_DIR / "google_drive_tokens.key"
REMOTE_SYNC_SECRET_FILE = DATA_DIR / "remote_sync_secret.json"
REMOTE_SYNC_SECRET_KEY_FILE = DATA_DIR / "remote_sync_secret.key"
CUSTOMER_TRACEROUTES_FILE = DATA_DIR / "customer_traceroutes.json"


def migrate_legacy_runtime_files() -> None:
    """Copy legacy checkout/bundle state into the persistent data directory once."""
    if os.environ.get("NMAPUI_SKIP_LEGACY_MIGRATION") == "1":
        return
    legacy_files = (
        (BASE_DIR / "config" / "customers.yaml", CUSTOMER_CONFIG_FILE),
        (BASE_DIR / "config" / "google_drive_credentials.json", GOOGLE_DRIVE_CREDENTIALS_FILE),
        (BASE_DIR / "data" / "scan_history.json", SCAN_HISTORY_FILE),
    )
    for source, destination in legacy_files:
        if not source.is_file() or destination.exists() or destination.is_symlink():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with source.open("rb") as source_file, tempfile.NamedTemporaryFile(
                prefix=f".{destination.name}.", dir=destination.parent, delete=False
            ) as temporary_file:
                temporary = Path(temporary_file.name)
                shutil.copyfileobj(source_file, temporary_file)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            temporary.chmod(0o600)
            os.link(temporary, destination)
        except FileExistsError:
            continue
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def resolve_scan_path(path: str) -> Optional[Path]:
    """Resolve a user-provided scan path and ensure it stays inside SCANS_DIR."""
    if not path:
        return None

    try:
        scan_dir = (SCANS_DIR / path).resolve()
        scans_root = SCANS_DIR.resolve()
    except (OSError, RuntimeError):
        return None

    try:
        scan_dir.relative_to(scans_root)
    except ValueError:
        return None

    return scan_dir
