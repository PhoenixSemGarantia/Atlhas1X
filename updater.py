"""Local-first updater for Atlhas1x.

The scanner itself works offline. This module contacts GitHub only to check for
an update and preserves reports, the embedded runtime, and preferences.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath

APP_DIR = Path(__file__).resolve().parent
REPOSITORY = "PhoenixSemGarantia/Atlhas1X"
MANIFEST_URL = f"https://raw.githubusercontent.com/{REPOSITORY}/main/version.json"
ARCHIVE_URL = f"https://github.com/{REPOSITORY}/archive/refs/heads/main.zip"

# Data created on the audited computer must never be replaced by an update.
PRESERVED_TOP_LEVEL_DIRECTORIES = {
    ".git", "__pycache__", "history", "repair_backup", "reports", "runtime", "temp"
}
PRESERVED_RELATIVE_FILES = {
    "config/update_preferences.json", "update_atlhas1x.bat"
}


def read_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def get_local_version() -> str:
    return str(read_json(APP_DIR / "version.json").get("version", "0.0.0"))


def get_remote_manifest() -> dict | None:
    try:
        request = urllib.request.Request(MANIFEST_URL, headers={"User-Agent": "Atlhas1x-Updater"})
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict) or not data.get("version"):
            raise ValueError("invalid version manifest")
        return data
    except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError):
        return None


def version_key(version: str) -> tuple[int, ...]:
    values = re.findall(r"\d+", str(version))
    return tuple(int(value) for value in values) or (0,)


def is_newer(remote: str, local: str) -> bool:
    remote_key, local_key = version_key(remote), version_key(local)
    length = max(len(remote_key), len(local_key))
    return remote_key + (0,) * (length - len(remote_key)) > local_key + (0,) * (length - len(local_key))


def should_preserve(relative: PurePosixPath) -> bool:
    if not relative.parts:
        return True
    if relative.parts[0].lower() in PRESERVED_TOP_LEVEL_DIRECTORIES:
        return True
    return relative.as_posix().lower() in PRESERVED_RELATIVE_FILES


def safe_extract_archive(archive: Path, destination: Path) -> Path:
    """Safely extract the single project directory in a GitHub source archive."""
    with zipfile.ZipFile(archive) as bundle:
        members = [name for name in bundle.namelist() if name and not name.endswith("/")]
        roots = {PurePosixPath(name).parts[0] for name in members if PurePosixPath(name).parts}
        if len(roots) != 1:
            raise ValueError("unexpected update package structure")
        prefix = f"{roots.pop()}/"
        for name in members:
            if not name.startswith(prefix):
                continue
            relative = PurePosixPath(name[len(prefix):])
            if not relative.parts or ".." in relative.parts:
                raise ValueError("unsafe file path in update package")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(name) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    return destination


def download_package(work_dir: Path) -> Path:
    archive = work_dir / "atlhas1x-update.zip"
    request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "Atlhas1x-Updater"})
    with urllib.request.urlopen(request, timeout=30) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    return archive


def replace_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.atlhas1x-new")
    shutil.copy2(source, temporary)
    os.replace(temporary, target)


def defer_self_replacement(source: Path) -> None:
    """Replace updater.py after this Python process exits on Windows."""
    target = APP_DIR / "updater.py"
    if os.name != "nt":
        replace_file(source, target)
        return

    work_dir = Path(tempfile.gettempdir()) / f"atlhas1x-update-{uuid.uuid4().hex}"
    work_dir.mkdir(parents=True, exist_ok=True)
    staged = work_dir / "updater.py"
    shutil.copy2(source, staged)
    script = work_dir / "finish-update.cmd"
    script.write_text(
        "@echo off\r\n"
        "timeout /t 2 /nobreak >nul\r\n"
        f'copy /y "{staged}" "{target}" >nul\r\n'
        "rmdir /s /q \"%~dp0\" >nul 2>&1\r\n",
        encoding="ascii",
    )
    subprocess.Popen(
        ["cmd.exe", "/c", str(script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def apply_package(package_dir: Path) -> int:
    copied = 0
    deferred_updater: Path | None = None
    current_updater = (APP_DIR / "updater.py").resolve()
    for source in package_dir.rglob("*"):
        if not source.is_file():
            continue
        relative = PurePosixPath(source.relative_to(package_dir).as_posix())
        if should_preserve(relative):
            continue
        target = APP_DIR.joinpath(*relative.parts)
        if target.resolve() == current_updater:
            deferred_updater = source
            continue
        replace_file(source, target)
        copied += 1
    if deferred_updater is not None:
        defer_self_replacement(deferred_updater)
        copied += 1
    return copied


def remove_manual_updater() -> None:
    try:
        (APP_DIR / "Update_Atlhas1x.bat").unlink(missing_ok=True)
    except OSError:
        pass


def perform_update(remote_version: str) -> tuple[bool, str]:
    temporary_root = Path(tempfile.mkdtemp(prefix="atlhas1x-update-"))
    try:
        package_dir = safe_extract_archive(download_package(temporary_root), temporary_root / "package")
        package_version = str(read_json(package_dir / "version.json").get("version", ""))
        if package_version != str(remote_version):
            return False, "The downloaded package version could not be verified."
        copied = apply_package(package_dir)
        return True, f"Atlhas1x was updated to v{remote_version} ({copied} files prepared)."
    except (OSError, ValueError, zipfile.BadZipFile, urllib.error.URLError, urllib.error.HTTPError):
        return False, "Update download or installation failed. The current version was kept."
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check or apply Atlhas1x updates.")
    parser.add_argument("--manual", action="store_true", help="show update information and ask before updating")
    parser.add_argument("--check", action="store_true", help="check availability without installing")
    parser.add_argument("--yes", action="store_true", help="apply an available update without asking")
    args = parser.parse_args(argv)

    local_version = get_local_version()
    remote = get_remote_manifest()
    if remote is None:
        if args.manual or args.check:
            print("[INFO] Update check unavailable. Atlhas1x will continue offline.")
        return 0

    remote_version = str(remote["version"])
    if not is_newer(remote_version, local_version):
        if args.manual or args.check:
            print(f"Atlhas1x is up to date (v{local_version}).")
        return 0
    if args.check:
        print(f"Update available: v{local_version} -> v{remote_version}")
        return 0

    if args.manual and not args.yes:
        print(f"\nInstalled: v{local_version}\nAvailable: v{remote_version}\n")
        try:
            answer = input("Install this update now? [Y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in {"y", "yes", "s", "sim"}:
            print("Update cancelled. The installed version was not changed.")
            return 0

    print(f"[INFO] Updating Atlhas1x: v{local_version} -> v{remote_version}...")
    success, message = perform_update(remote_version)
    print(("[OK] " if success else "[WARN] ") + message)
    if success:
        remove_manual_updater()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
