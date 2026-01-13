#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
except Exception:
    Console = None  # type: ignore

REPO_ROOT_SENTINELS = ("ports", "versions")


def _console():
    if Console is None:
        return None
    return Console()


def die(msg: str, code: int = 2) -> None:
    c = _console()
    if c:
        c.print(f"[red]error:[/red] {msg}")
    else:
        print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    # Print command in debug mode
    if os.environ.get("REGISTRY_DEBUG") == "1":
        print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check, text=True, capture_output=True)


def repo_root(start: Optional[Path] = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for _ in range(40):
        if all((p / s).exists() for s in REPO_ROOT_SENTINELS):
            return p
        if p.parent == p:
            break
        p = p.parent
    die("Could not find repo root (expected folders: ports/ and versions/). Run from within the registry repo.")


def ensure_git_available() -> None:
    if shutil.which("git") is None:
        die("git not found in PATH")


def ensure_vcpkg(vcpkg_path: Optional[str]) -> str:
    if vcpkg_path:
        vp = Path(vcpkg_path).expanduser().resolve()
        if vp.exists():
            return str(vp)
        die(f"vcpkg not found at: {vp}")
    # Try env var first
    env = os.environ.get("VCPKG")
    if env:
        vp = Path(env).expanduser().resolve()
        if vp.exists():
            return str(vp)
    # Try PATH
    which = shutil.which("vcpkg")
    if which:
        return which
    die("vcpkg executable not found. Provide --vcpkg /path/to/vcpkg or set VCPKG env var or put vcpkg in PATH.")


def list_ports(root: Path) -> List[str]:
    ports_dir = root / "ports"
    if not ports_dir.exists():
        return []
    ports = [p.name for p in ports_dir.iterdir() if p.is_dir()]
    ports.sort()
    return ports


def read_port_manifest_version(port_dir: Path) -> Tuple[Optional[str], Optional[int]]:
    """
    Returns (version_string, port_version_int). version_string may be None if not found.
    """
    manifest = port_dir / "vcpkg.json"
    if not manifest.exists():
        return (None, None)
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"Failed to parse {manifest}: {e}")

    # vcpkg accepts version, version-string, version-semver, version-date. We treat any as a string.
    version = (
        data.get("version")
        or data.get("version-string")
        or data.get("version-semver")
        or data.get("version-date")
    )
    pv = data.get("port-version")
    if pv is not None and not isinstance(pv, int):
        die(f"{manifest}: 'port-version' must be an integer")
    if version is not None and not isinstance(version, str):
        # some folks use numeric for "version"; normalize to str
        version = str(version)
    return (version, pv)


def git_is_shallow(root: Path) -> bool:
    try:
        r = run(["git", "rev-parse", "--is-shallow-repository"], cwd=root)
        return r.stdout.strip() == "true"
    except subprocess.CalledProcessError:
        return False


def git_unshallow(root: Path) -> None:
    # Works for both older/newer git; if already full, harmless
    try:
        run(["git", "fetch", "--unshallow"], cwd=root, check=True)
    except subprocess.CalledProcessError:
        # fall back
        run(["git", "fetch", "--depth=2147483647"], cwd=root, check=True)


def changed_ports_since(root: Path, base_ref: str) -> List[str]:
    """
    Returns list of port names whose files under ports/<name>/ changed compared to base_ref.
    """
    ensure_git_available()
    try:
        run(["git", "rev-parse", "--verify", base_ref], cwd=root)
    except subprocess.CalledProcessError:
        die(f"Base ref '{base_ref}' not found. Fetch it or choose another (e.g. origin/main).")

    cp = run(["git", "diff", "--name-only", f"{base_ref}...HEAD"], cwd=root)
    changed_files = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
    ports: set[str] = set()
    for f in changed_files:
        if f.startswith("ports/"):
            parts = f.split("/")
            if len(parts) >= 2:
                ports.add(parts[1])
    return sorted(ports)


def vcpkg_x_add_version(
    root: Path,
    vcpkg_exe: str,
    port: str,
    overwrite: bool,
) -> None:
    ports_root = root / "ports"
    versions_dir = root / "versions"

    if not (ports_root / port).exists():
        die(f"Port '{port}' not found under {ports_root}")

    cmd = [
        vcpkg_exe,
        "x-add-version",
        f"--x-builtin-ports-root={ports_root}",
        f"--x-builtin-registry-versions-dir={versions_dir}",
        port,
        "--x-wait-for-lock",
    ]
    if overwrite:
        cmd.insert(-2, "--overwrite-version")

    cp = subprocess.run(cmd, cwd=str(root), text=True)
    if cp.returncode != 0:
        die(f"vcpkg x-add-version failed for {port} (exit {cp.returncode})")


def validate_registry(root: Path) -> None:
    """
    Lightweight sanity checks:
    - ports/<port>/vcpkg.json exists and has some version field
    - versions/baseline.json exists
    - versions/<letter>-/<port>.json exists for each port in baseline (best effort)
    """
    versions_dir = root / "versions"
    baseline = versions_dir / "baseline.json"
    if not baseline.exists():
        die("versions/baseline.json missing")

    try:
        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"Failed to parse versions/baseline.json: {e}")

    if "default" not in baseline_data or not isinstance(baseline_data["default"], dict):
        die("versions/baseline.json should contain a 'default' object mapping port->version")

    ports_in_baseline = sorted(baseline_data["default"].keys())
    missing_ports_dirs = []
    missing_versions_files = []
    missing_manifest_version = []

    for port in ports_in_baseline:
        port_dir = root / "ports" / port
        if not port_dir.exists():
            missing_ports_dirs.append(port)
            continue

        version, _pv = read_port_manifest_version(port_dir)
        if not version:
            missing_manifest_version.append(port)

        # versions file naming: versions/<first-letter>-/<port>.json
        bucket = (port[0].lower() if port else "_") + "-"
        vf = versions_dir / bucket / f"{port}.json"
        if not vf.exists():
            missing_versions_files.append(str(vf.relative_to(root)))

    c = _console()
    ok = True

    def report_list(title: str, items: List[str]) -> None:
        nonlocal ok
        if not items:
            return
        ok = False
        if c:
            c.print(f"[red]{title}[/red]")
            for it in items:
                c.print(f"  - {it}")
        else:
            print(title, file=sys.stderr)
            for it in items:
                print("  -", it, file=sys.stderr)

    report_list("Missing ports/ directories for ports listed in baseline:", missing_ports_dirs)
    report_list("Ports missing a version field in ports/<port>/vcpkg.json:", missing_manifest_version)
    report_list("Missing versions file(s):", missing_versions_files)

    if ok:
        if c:
            c.print("[green]Validation OK[/green]")
        else:
            print("Validation OK")


def cmd_list_ports(args: argparse.Namespace) -> None:
    root = repo_root()
    ports = list_ports(root)
    c = _console()
    if c:
        t = Table(title="Ports")
        t.add_column("Port")
        t.add_column("Version (from vcpkg.json)")
        t.add_column("Port-Version")
        for p in ports:
            ver, pv = read_port_manifest_version(root / "ports" / p)
            t.add_row(p, ver or "", "" if pv is None else str(pv))
        c.print(t)
    else:
        for p in ports:
            print(p)


def cmd_changed_ports(args: argparse.Namespace) -> None:
    root = repo_root()
    ports = changed_ports_since(root, args.base)
    for p in ports:
        print(p)


def cmd_add_version(args: argparse.Namespace) -> None:
    root = repo_root()
    ensure_git_available()
    vcpkg_exe = ensure_vcpkg(args.vcpkg)

    if git_is_shallow(root):
        # To avoid missing tree objects, unshallow.
        if args.unshallow:
            git_unshallow(root)
        else:
            die("Registry repo is shallow. Re-run with --unshallow or run: git fetch --unshallow")

    ports = []
    if args.all:
        ports = list_ports(root)
        if not ports:
            die("No ports found under ports/")
    else:
        ports = args.ports
        if not ports:
            die("No ports specified. Provide port names or use --all")

    for port in ports:
        vcpkg_x_add_version(root, vcpkg_exe, port, overwrite=args.overwrite)

    print("Done. Remember to commit and push changes under versions/ (and ports/ if you modified them).")


def cmd_regen_changed(args: argparse.Namespace) -> None:
    root = repo_root()
    ensure_git_available()
    vcpkg_exe = ensure_vcpkg(args.vcpkg)

    if git_is_shallow(root):
        if args.unshallow:
            git_unshallow(root)
        else:
            die("Registry repo is shallow. Re-run with --unshallow or run: git fetch --unshallow")

    ports = changed_ports_since(root, args.base)
    if not ports:
        print("No changed ports detected.")
        return

    for port in ports:
        vcpkg_x_add_version(root, vcpkg_exe, port, overwrite=args.overwrite)

    print("Done. Commit versions/ (and ports/).")


def cmd_validate(args: argparse.Namespace) -> None:
    root = repo_root()
    validate_registry(root)


def main() -> None:
    ap = argparse.ArgumentParser(prog="registry.py", description="Utilities for maintaining a vcpkg git registry")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list-ports", help="List ports in this registry")
    sp.set_defaults(func=cmd_list_ports)

    sp = sub.add_parser("changed-ports", help="List ports changed since a git ref (default: origin/main)")
    sp.add_argument("--base", default="origin/main", help="Git ref to diff against (origin/main, main, HEAD~1, etc)")
    sp.set_defaults(func=cmd_changed_ports)

    sp = sub.add_parser("add-version", help="Run vcpkg x-add-version for one or more ports (using this registry's ports/ and versions/)")
    sp.add_argument("ports", nargs="*", help="Port names (directory names under ports/)")
    sp.add_argument("--all", action="store_true", help="Run for all ports in ports/")
    sp.add_argument("--overwrite", action="store_true", help="Overwrite existing version entries")
    sp.add_argument("--vcpkg", default=None, help="Path to vcpkg executable (or set env VCPKG)")
    sp.add_argument("--unshallow", action="store_true", help="If repo is shallow, fetch full history automatically")
    sp.set_defaults(func=cmd_add_version)

    sp = sub.add_parser("regen-changed", help="Regenerate metadata for ports changed vs base ref")
    sp.add_argument("--base", default="origin/main", help="Git ref to diff against (origin/main, main, etc)")
    sp.add_argument("--overwrite", action="store_true", help="Overwrite existing version entries")
    sp.add_argument("--vcpkg", default=None, help="Path to vcpkg executable (or set env VCPKG)")
    sp.add_argument("--unshallow", action="store_true", help="If repo is shallow, fetch full history automatically")
    sp.set_defaults(func=cmd_regen_changed)

    sp = sub.add_parser("validate", help="Validate baseline + versions files exist and port manifests contain a version")
    sp.set_defaults(func=cmd_validate)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
