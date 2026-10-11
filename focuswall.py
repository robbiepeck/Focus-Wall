#!/usr/bin/env python3
"""
FocusWall: a local macOS distraction-site blocker.

The daemon enforces a hosts-file block list on weekdays and removes it on
weekends, using Australia/Brisbane time by default.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import plistlib
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from zoneinfo import ZoneInfo


APP_NAME = "FocusWall"
LABEL = "com.pecksol.focuswall"
BEGIN_MARKER = "# BEGIN FOCUSWALL MANAGED BLOCK"
END_MARKER = "# END FOCUSWALL MANAGED BLOCK"
DEFAULT_TIMEZONE = "Australia/Brisbane"
DEFAULT_DELAY_MINUTES = 30
DEFAULT_UNLOCK_MINUTES = 60
PBKDF2_ITERATIONS = 310_000

SYSTEM_STATE_DIR = Path("/Library/Application Support/FocusWall")
SYSTEM_INSTALL_DIR = Path("/usr/local/lib/focuswall")
SYSTEM_BIN = Path("/usr/local/bin/focuswall")
SYSTEM_PLIST = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
SYSTEM_HOSTS = Path("/etc/hosts")
SYSTEM_LOG = Path("/Library/Logs/FocusWall.log")
SYSTEM_ERR_LOG = Path("/Library/Logs/FocusWall.err.log")

DEFAULT_DOMAINS = [
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "studio.youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com",
    "ytimg.com",
    "www.ytimg.com",
    "i.ytimg.com",
    "googlevideo.com",
    "www.googlevideo.com",
    "x.com",
    "www.x.com",
    "twitter.com",
    "www.twitter.com",
    "mobile.twitter.com",
    "t.co",
    "tweetdeck.twitter.com",
    "linkedin.com",
    "www.linkedin.com",
    "m.linkedin.com",
    "lnkd.in",
    "reddit.com",
    "www.reddit.com",
    "old.reddit.com",
    "new.reddit.com",
    "m.reddit.com",
    "redd.it",
    "instagram.com",
    "www.instagram.com",
    "m.instagram.com",
    "facebook.com",
    "www.facebook.com",
    "m.facebook.com",
    "fb.com",
    "fb.watch",
    "messenger.com",
    "www.messenger.com",
    "tiktok.com",
    "www.tiktok.com",
    "m.tiktok.com",
    "vm.tiktok.com",
    "twitch.tv",
    "www.twitch.tv",
    "m.twitch.tv",
    "netflix.com",
    "www.netflix.com",
    "discord.com",
    "www.discord.com",
    "discord.gg",
    "discordapp.com",
    "www.discordapp.com",
    "news.ycombinator.com",
    "cnn.com",
    "www.cnn.com",
    "bbc.com",
    "www.bbc.com",
    "bbc.co.uk",
    "www.bbc.co.uk",
    "nytimes.com",
    "www.nytimes.com",
    "washingtonpost.com",
    "www.washingtonpost.com",
    "theguardian.com",
    "www.theguardian.com",
    "abc.net.au",
    "www.abc.net.au",
    "news.com.au",
    "www.news.com.au",
    "smh.com.au",
    "www.smh.com.au",
    "theage.com.au",
    "www.theage.com.au",
]


@dataclass(frozen=True)
class Paths:
    state_dir: Path
    install_dir: Path
    bin_path: Path
    plist_path: Path
    hosts_path: Path
    log_path: Path
    err_log_path: Path

    @property
    def config_path(self) -> Path:
        return self.state_dir / "config.json"


def paths() -> Paths:
    return Paths(
        state_dir=Path(os.environ.get("FOCUSWALL_STATE_DIR", SYSTEM_STATE_DIR)),
        install_dir=Path(os.environ.get("FOCUSWALL_INSTALL_DIR", SYSTEM_INSTALL_DIR)),
        bin_path=Path(os.environ.get("FOCUSWALL_BIN", SYSTEM_BIN)),
        plist_path=Path(os.environ.get("FOCUSWALL_PLIST", SYSTEM_PLIST)),
        hosts_path=Path(os.environ.get("FOCUSWALL_HOSTS", SYSTEM_HOSTS)),
        log_path=Path(os.environ.get("FOCUSWALL_LOG", SYSTEM_LOG)),
        err_log_path=Path(os.environ.get("FOCUSWALL_ERR_LOG", SYSTEM_ERR_LOG)),
    )


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root(action: str) -> None:
    if not is_root():
        raise SystemExit(f"{action} requires admin/root privileges. Run with sudo.")


def utc_now() -> datetime:
    override = os.environ.get("FOCUSWALL_NOW_UTC")
    if override:
        return datetime.fromisoformat(override.replace("Z", "+00:00")).astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def local_now(config: dict) -> datetime:
    return utc_now().astimezone(ZoneInfo(config.get("timezone", DEFAULT_TIMEZONE)))


def is_weekend_now(config: dict) -> bool:
    now = local_now(config)
    return now.weekday() in (5, 6)


def normalize_domains(domains: Iterable[str]) -> list[str]:
    cleaned: set[str] = set()
    for domain in domains:
        domain = domain.strip().lower()
        if not domain or domain.startswith("#"):
            continue
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/", 1)[0]
        domain = domain.strip(".")
        if domain:
            cleaned.add(domain)
    return sorted(cleaned)


def hash_recovery_key(key: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, iterations)


def make_recovery_key() -> str:
    # Grouped to make it printable and less typo-prone while still high entropy.
    raw = secrets.token_urlsafe(36).replace("-", "").replace("_", "")
    return "-".join(raw[i : i + 6] for i in range(0, 36, 6))


def verify_recovery_key(config: dict, key: str) -> bool:
    salt = base64.b64decode(config["recovery_salt_b64"])
    expected = base64.b64decode(config["recovery_hash_b64"])
    actual = hash_recovery_key(key, salt, int(config["pbkdf2_iterations"]))
    return secrets.compare_digest(actual, expected)


def read_config(p: Paths) -> dict:
    if not p.config_path.exists():
        raise SystemExit(f"{APP_NAME} is not installed yet. Missing {p.config_path}.")
    with p.config_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_config(p: Paths, config: dict) -> None:
    p.state_dir.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix="config.", suffix=".json", dir=str(p.state_dir))
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp_name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.replace(tmp_name, p.config_path)


def make_config(recovery_key: str) -> dict:
    salt = secrets.token_bytes(32)
    digest = hash_recovery_key(recovery_key, salt)
    return {
        "version": 1,
        "timezone": DEFAULT_TIMEZONE,
        "domains": normalize_domains(DEFAULT_DOMAINS),
        "recovery_salt_b64": base64.b64encode(salt).decode("ascii"),
        "recovery_hash_b64": base64.b64encode(digest).decode("ascii"),
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "pending_unlock_effective_at_utc": None,
        "unlock_until_utc": None,
        "last_policy": None,
        "created_at_utc": utc_now().isoformat(),
    }


def split_hosts(text: str) -> tuple[str, str, str]:
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        return text.rstrip() + "\n", "", ""
    end_line = text.find("\n", end)
    if end_line == -1:
        end_line = len(text)
    else:
        end_line += 1
    return text[:start].rstrip() + "\n", text[start:end_line], text[end_line:].lstrip("\n")


def managed_block(domains: Iterable[str]) -> str:
    lines = [BEGIN_MARKER]
    for domain in normalize_domains(domains):
        lines.append(f"0.0.0.0 {domain}")
        lines.append(f"::1 {domain}")
    lines.append(END_MARKER)
    return "\n".join(lines) + "\n"


def hosts_with_policy(existing: str, domains: Iterable[str], should_block: bool) -> str:
    before, _managed, after = split_hosts(existing)
    body = managed_block(domains) if should_block else ""
    return (before + body + after).rstrip() + "\n"


def write_hosts_if_changed(p: Paths, domains: Iterable[str], should_block: bool) -> bool:
    existing = p.hosts_path.read_text(encoding="utf-8")
    updated = hosts_with_policy(existing, domains, should_block)
    if updated == existing:
        return False
    backup = p.hosts_path.with_name(f"{p.hosts_path.name}.focuswall.bak")
    if not backup.exists():
        shutil.copy2(p.hosts_path, backup)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix="hosts.", dir=str(p.hosts_path.parent))
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
        fh.write(updated)
    shutil.copymode(p.hosts_path, tmp_name)
    os.replace(tmp_name, p.hosts_path)
    return True


def flush_dns() -> None:
    if os.environ.get("FOCUSWALL_SKIP_DNS_FLUSH") == "1":
        return
    for cmd in (["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]):
        try:
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def update_unlock_state(config: dict, now: datetime) -> tuple[bool, str | None]:
    changed = False
    pending = parse_utc(config.get("pending_unlock_effective_at_utc"))
    unlock_until = parse_utc(config.get("unlock_until_utc"))
    if pending and pending <= now:
        duration = int(config.get("pending_unlock_duration_minutes", DEFAULT_UNLOCK_MINUTES))
        unlock_until = now + timedelta(minutes=duration)
        config["unlock_until_utc"] = unlock_until.isoformat()
        config["pending_unlock_effective_at_utc"] = None
        config["pending_unlock_duration_minutes"] = None
        changed = True
    if unlock_until and unlock_until <= now:
        config["unlock_until_utc"] = None
        changed = True
    active = parse_utc(config.get("unlock_until_utc"))
    return changed, active.isoformat() if active and active > now else None


def desired_policy(config: dict, now: datetime) -> tuple[bool, str]:
    changed, unlock_until = update_unlock_state(config, now)
    weekend = is_weekend_now(config)
    if weekend:
        return False, "weekend"
    if unlock_until:
        return False, f"emergency unlock until {unlock_until}"
    return True, "weekday"


def apply_policy(p: Paths, config: dict) -> tuple[bool, str, bool]:
    now = utc_now()
    unlock_state_changed, _unlock_until = update_unlock_state(config, now)
    should_block, reason = desired_policy(config, now)
    hosts_changed = write_hosts_if_changed(p, config["domains"], should_block)
    config["last_policy"] = {
        "blocked": should_block,
        "reason": reason,
        "checked_at_utc": now.isoformat(),
        "local_time": local_now(config).isoformat(),
    }
    if hosts_changed or unlock_state_changed:
        write_config(p, config)
    if hosts_changed:
        flush_dns()
    return should_block, reason, hosts_changed


def write_plist(p: Paths) -> None:
    plist = {
        "Label": LABEL,
        "ProgramArguments": [str(p.bin_path), "daemon"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(p.log_path),
        "StandardErrorPath": str(p.err_log_path),
    }
    p.plist_path.parent.mkdir(parents=True, exist_ok=True)
    with p.plist_path.open("wb") as fh:
        plistlib.dump(plist, fh)
    os.chmod(p.plist_path, 0o644)


def run_launchctl(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], check=check, text=True, capture_output=True)


def copy_program(p: Paths, source: Path) -> None:
    p.install_dir.mkdir(parents=True, exist_ok=True)
    target = p.install_dir / "focuswall.py"
    shutil.copy2(source, target)
    os.chmod(target, 0o755)
    p.bin_path.parent.mkdir(parents=True, exist_ok=True)
    python = Path(sys.executable).resolve()
    wrapper = f"#!/bin/sh\nexec {python!s} {target!s} \"$@\"\n"
    p.bin_path.write_text(wrapper, encoding="utf-8")
    os.chmod(p.bin_path, 0o755)


def install(args: argparse.Namespace) -> None:
    require_root("install")
    p = paths()
    if p.config_path.exists() and not args.force:
        raise SystemExit(f"{APP_NAME} already appears installed. Use --force to reinstall.")
    recovery_key = make_recovery_key()
    p.state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(p.state_dir, 0o755)
    copy_program(p, Path(__file__).resolve())
    write_config(p, make_config(recovery_key))
    write_plist(p)
    apply_policy(p, read_config(p))
    run_launchctl(["bootout", "system", str(p.plist_path)], check=False)
    result = run_launchctl(["bootstrap", "system", str(p.plist_path)], check=False)
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or "launchctl bootstrap failed")
    run_launchctl(["kickstart", "-k", f"system/{LABEL}"], check=False)
    print(
        textwrap.dedent(
            f"""
            {APP_NAME} installed.

            Store this recovery key somewhere inconvenient but recoverable:

                {recovery_key}

            Weekday emergency unlocks require this key, sudo, and a {DEFAULT_DELAY_MINUTES}-minute delay.
            """
        ).strip()
    )


def daemon(_args: argparse.Namespace) -> None:
    p = paths()
    running = True

    def stop(_signum, _frame) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        try:
            config = read_config(p)
            blocked, reason, changed = apply_policy(p, config)
            if changed:
                state = "blocked" if blocked else "allowed"
                print(f"{datetime.now().isoformat()} policy changed: {state} ({reason})", flush=True)
        except Exception as exc:  # noqa: BLE001 - daemon should keep enforcing on transient issues.
            print(f"{datetime.now().isoformat()} error: {exc}", file=sys.stderr, flush=True)
        time.sleep(30)


def status(_args: argparse.Namespace) -> None:
    p = paths()
    config = read_config(p)
    should_block, reason = desired_policy(config, utc_now())
    pending = config.get("pending_unlock_effective_at_utc")
    unlock_until = config.get("unlock_until_utc")
    print(f"Timezone: {config.get('timezone', DEFAULT_TIMEZONE)}")
    print(f"Local time: {local_now(config).isoformat(timespec='seconds')}")
    print(f"Policy: {'blocked' if should_block else 'allowed'} ({reason})")
    if pending:
        print(f"Pending emergency unlock: {pending}")
    if unlock_until:
        print(f"Emergency unlock active until: {unlock_until}")
    print(f"Blocked domains: {len(config['domains'])}")
    print(f"LaunchDaemon: {p.plist_path}")
    print(f"Hosts file: {p.hosts_path}")


def prompt_and_verify(config: dict) -> None:
    key = getpass.getpass("Recovery key: ")
    if not verify_recovery_key(config, key):
        raise SystemExit("Recovery key did not match.")


def emergency_unlock(args: argparse.Namespace) -> None:
    require_root("emergency unlock")
    p = paths()
    config = read_config(p)
    prompt_and_verify(config)
    now = utc_now()
    effective_at = now + timedelta(minutes=args.delay_minutes)
    config["pending_unlock_effective_at_utc"] = effective_at.isoformat()
    config["pending_unlock_duration_minutes"] = args.duration_minutes
    write_config(p, config)
    apply_policy(p, read_config(p))
    print(
        f"Emergency unlock scheduled for {effective_at.isoformat()} UTC "
        f"and will last {args.duration_minutes} minutes."
    )


def cancel_unlock(_args: argparse.Namespace) -> None:
    require_root("cancel unlock")
    p = paths()
    config = read_config(p)
    config["pending_unlock_effective_at_utc"] = None
    config["pending_unlock_duration_minutes"] = None
    config["unlock_until_utc"] = None
    write_config(p, config)
    apply_policy(p, read_config(p))
    print("Emergency unlock cancelled and weekday block restored if applicable.")


def block_now(_args: argparse.Namespace) -> None:
    require_root("block now")
    p = paths()
    config = read_config(p)
    config["pending_unlock_effective_at_utc"] = None
    config["pending_unlock_duration_minutes"] = None
    config["unlock_until_utc"] = None
    write_config(p, config)
    _blocked, reason, _changed = apply_policy(p, read_config(p))
    print(f"Block state refreshed ({reason}).")


def uninstall(args: argparse.Namespace) -> None:
    require_root("uninstall")
    p = paths()
    config = read_config(p)
    if not args.skip_key:
        prompt_and_verify(config)
    run_launchctl(["bootout", "system", str(p.plist_path)], check=False)
    if p.hosts_path.exists():
        existing = p.hosts_path.read_text(encoding="utf-8")
        cleaned = hosts_with_policy(existing, [], False)
        if cleaned != existing:
            p.hosts_path.write_text(cleaned, encoding="utf-8")
            flush_dns()
    for path in (p.plist_path, p.bin_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if p.install_dir.exists():
        shutil.rmtree(p.install_dir)
    if args.keep_config:
        print(f"Uninstalled daemon and hosts block. Kept config at {p.state_dir}.")
    else:
        shutil.rmtree(p.state_dir, ignore_errors=True)
        print("Uninstalled daemon, hosts block, and config.")


def add_domain(args: argparse.Namespace) -> None:
    require_root("add domain")
    p = paths()
    config = read_config(p)
    config["domains"] = normalize_domains([*config["domains"], *args.domains])
    write_config(p, config)
    apply_policy(p, read_config(p))
    print(f"Domain list now has {len(config['domains'])} entries.")


def remove_domain(args: argparse.Namespace) -> None:
    require_root("remove domain")
    p = paths()
    config = read_config(p)
    remove = set(normalize_domains(args.domains))
    config["domains"] = [d for d in normalize_domains(config["domains"]) if d not in remove]
    write_config(p, config)
    apply_policy(p, read_config(p))
    print(f"Domain list now has {len(config['domains'])} entries.")


def list_domains(_args: argparse.Namespace) -> None:
    config = read_config(paths())
    for domain in normalize_domains(config["domains"]):
        print(domain)


def self_test(_args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        os.environ["FOCUSWALL_STATE_DIR"] = str(temp / "state")
        os.environ["FOCUSWALL_HOSTS"] = str(temp / "hosts")
        os.environ["FOCUSWALL_SKIP_DNS_FLUSH"] = "1"
        p = paths()
        p.hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        key = "test-key"
        write_config(p, make_config(key))
        config = read_config(p)
        os.environ["FOCUSWALL_NOW_UTC"] = "2026-10-12T00:00:00+00:00"
        blocked, _reason, changed = apply_policy(p, config)
        assert blocked is True
        assert changed is True
        assert "0.0.0.0 youtube.com" in p.hosts_path.read_text(encoding="utf-8")
        os.environ["FOCUSWALL_NOW_UTC"] = "2026-10-10T00:00:00+00:00"
        blocked, _reason, changed = apply_policy(p, read_config(p))
        assert blocked is False
        assert changed is True
        assert BEGIN_MARKER not in p.hosts_path.read_text(encoding="utf-8")
        assert verify_recovery_key(read_config(p), key)
    print("self-test passed")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="macOS weekday distraction-site blocker")
    sub = p.add_subparsers(dest="command", required=True)

    install_p = sub.add_parser("install", help="install LaunchDaemon and generate a recovery key")
    install_p.add_argument("--force", action="store_true", help="overwrite an existing FocusWall install")
    install_p.set_defaults(func=install)

    sub.add_parser("daemon", help=argparse.SUPPRESS).set_defaults(func=daemon)
    sub.add_parser("status", help="show current policy status").set_defaults(func=status)

    unlock_p = sub.add_parser("emergency-unlock", help="schedule a delayed weekday unlock")
    unlock_p.add_argument("--delay-minutes", type=int, default=DEFAULT_DELAY_MINUTES)
    unlock_p.add_argument("--duration-minutes", type=int, default=DEFAULT_UNLOCK_MINUTES)
    unlock_p.set_defaults(func=emergency_unlock)

    sub.add_parser("cancel-unlock", help="cancel pending or active emergency unlock").set_defaults(func=cancel_unlock)
    sub.add_parser("block-now", help="cancel unlocks and reapply the current policy").set_defaults(func=block_now)

    uninstall_p = sub.add_parser("uninstall", help="remove LaunchDaemon and managed hosts entries")
    uninstall_p.add_argument("--keep-config", action="store_true", help="keep recovery config after uninstall")
    uninstall_p.add_argument("--skip-key", action="store_true", help=argparse.SUPPRESS)
    uninstall_p.set_defaults(func=uninstall)

    add_p = sub.add_parser("add-domain", help="add domains to the block list")
    add_p.add_argument("domains", nargs="+")
    add_p.set_defaults(func=add_domain)

    remove_p = sub.add_parser("remove-domain", help="remove domains from the block list")
    remove_p.add_argument("domains", nargs="+")
    remove_p.set_defaults(func=remove_domain)

    sub.add_parser("list-domains", help="print blocked domains").set_defaults(func=list_domains)
    sub.add_parser("self-test", help="run local tests without touching system files").set_defaults(func=self_test)
    return p


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
