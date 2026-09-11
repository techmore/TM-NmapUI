import logging
import os
import platform
import sys
from datetime import datetime
from typing import Optional

import requests

from .paths import VERSION_FILE


logger = logging.getLogger(__name__)
APP_VERSION = None

# Only release downloads from our own GitHub org may ever be surfaced to the UI.
_ALLOWED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}


def _validate_download_url(url) -> str | None:
    """Return the URL only if it is https and points at an allowed host."""
    if not url or not isinstance(url, str):
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
    except (ValueError, AttributeError):
        return None
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
        logger.warning("Rejected untrusted update download URL: %r", url)
        return None
    return url


def env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean environment flag."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_app_version():
    """Read or generate app version based on timestamp."""
    global APP_VERSION

    if APP_VERSION:
        return APP_VERSION

    if VERSION_FILE.exists():
        APP_VERSION = VERSION_FILE.read_text().strip()
        return APP_VERSION

    now = datetime.now()
    APP_VERSION = f"v{now.year}.{now.month}.{now.day}.{now.hour:02d}_{now.minute:02d}"
    return APP_VERSION


def _parse_version(version: str):
    if not version.startswith("v"):
        return (0, 0, 0, 0, 0)

    parts = version[1:].split(".")
    if len(parts) != 4:
        return (0, 0, 0, 0, 0)

    try:
        year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
        hour_min = parts[3].split("_")
        hour, minute = int(hour_min[0]), int(hour_min[1]) if len(hour_min) > 1 else 0
        return (year, month, day, hour, minute)
    except (ValueError, IndexError):
        return (0, 0, 0, 0, 0)


def _select_release_asset(release: dict, *, platform_name: Optional[str] = None, machine: Optional[str] = None):
    platform_name = platform_name or sys.platform
    machine = (machine or platform.machine()).lower()
    assets = release.get("assets") or []
    if not assets:
        return None

    if platform_name == "darwin":
        extension_order = (".dmg", ".pkg", ".zip")
        architecture_hints = []
        if machine in {"arm64", "aarch64"}:
            architecture_hints = ["arm64", "aarch64", "apple-silicon"]
        elif machine in {"x86_64", "amd64"}:
            architecture_hints = ["x86_64", "amd64", "intel"]

        for extension in extension_order:
            matching_extension = [
                asset
                for asset in assets
                if str(asset.get("name", "")).lower().endswith(extension)
            ]
            for hint in architecture_hints:
                for asset in matching_extension:
                    if hint in str(asset.get("name", "")).lower():
                        return asset
            if matching_extension:
                return matching_extension[0]

    return assets[0]


def check_for_updates():
    """Check for new releases on GitHub."""
    current_version = get_app_version()
    try:
        response = requests.get(
            "https://api.github.com/repos/techmore/TM-NmapUI/releases/latest", timeout=10
        )
        response.raise_for_status()
        latest_release = response.json()
        latest_version = latest_release["tag_name"]
        selected_asset = _select_release_asset(latest_release)
        release_url = latest_release.get("html_url") or latest_release.get("url")
        download_url = (
            selected_asset.get("browser_download_url")
            if isinstance(selected_asset, dict)
            else None
        )
        asset_name = selected_asset.get("name") if isinstance(selected_asset, dict) else None

        if _parse_version(latest_version) > _parse_version(current_version):
            return {
                "available": True,
                "current_version": current_version,
                "latest_version": latest_version,
                "release_url": _validate_download_url(release_url) or "",
                "download_url": _validate_download_url(download_url)
                or _validate_download_url(release_url)
                or "",
                "asset_name": asset_name,
                "install_method": "manual_download",
                "release_notes": latest_release["body"],
            }
        return {
            "available": False,
            "current_version": current_version,
            "latest_version": latest_version,
            "release_url": release_url,
        }
    except Exception as exc:
        logger.error("Failed to check for updates: %s", exc)
        return {"available": False, "current_version": current_version, "error": str(exc)}


def restart_application():
    """Restart the application process."""
    logger.info("Restarting application...")
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        logger.error("Failed to restart application: %s", exc)
        sys.exit(1)
