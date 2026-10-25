#!/usr/bin/env python3
"""Drive TunPcap captures over adb: start, stop, pull.

    tunpcap.py start --serial S --app com.android.chrome [--name x.pcap]
    tunpcap.py stop  --serial S
    tunpcap.py pull  --serial S --name x.pcap --out DIR

Every start may show the system VPN consent dialog (whenever another app,
e.g. FlClash, took the VPN since the last capture); tap it on the phone.
"""
from __future__ import annotations

import argparse
import shlex
import struct
import subprocess
import sys
import time
from pathlib import Path

PKG = "dev.plat1ko.tunpcap"
CTRL = f"{PKG}/.CaptureCtrl"
PHONE_DIR = "/sdcard/Download/TunPcap"
LOG_TAG = "TunPcap"

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_RAW = 101

OUTCOME_WAIT_SECONDS = 15
PULL_WAIT_SECONDS = 30
POLL_SECONDS = 0.5


def build_start_args(apps: list[str], name: str | None) -> list[str]:
    args = [
        "am", "start", "-n", CTRL,
        "--es", "action", "start",
        "--es", "pcap_dump_mode", "pcap_file",
        "--es", "app_filter", ",".join(apps),
        "--ez", "full_payload", "true",
    ]
    if name:
        args += ["--es", "pcap_name", name]
    return args


def build_stop_args() -> list[str]:
    return ["am", "start", "-n", CTRL, "--es", "action", "stop"]


def capture_outcome(logcat: str) -> tuple[str, str] | None:
    """First decisive TunPcap log line: ("started"|"rejected", message), or None yet.

    The app logs "started" only after the profile is loaded, GLOBAL is verified and
    the VPN is up, so traffic of the captured apps already leaves via the proxy.
    """
    for line in logcat.splitlines():
        head, sep, message = line.partition(": ")
        if not sep or not head.rstrip().endswith(f" {LOG_TAG}"):
            continue
        message = message.strip()
        if message.startswith("started "):
            return "started", message
        if message.startswith("rejected:"):
            return "rejected", message
    return None


def check_pcap_header(head: bytes) -> int:
    if len(head) < 24:
        raise ValueError(f"pcap header too short: {len(head)} bytes")
    magic, major, minor = struct.unpack_from("<IHH", head, 0)
    if magic != PCAP_MAGIC or (major, minor) != (2, 4):
        raise ValueError(f"not a little-endian pcap 2.4 file (magic={magic:#x})")
    linktype = struct.unpack_from("<I", head, 20)[0]
    if linktype != LINKTYPE_RAW:
        raise ValueError(f"linktype {linktype}, want {LINKTYPE_RAW} (raw IP)")
    return linktype


# --- adb plumbing -----------------------------------------------------------

def adb(serial: str, *args: str, timeout: int = 60) -> str:
    r = subprocess.run(["adb", "-s", serial, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def adb_shell(serial: str, args: list[str]) -> str:
    return adb(serial, "shell", " ".join(shlex.quote(a) for a in args))


def device_now(serial: str) -> str:
    """Phone clock in logcat's -T format, so we only read lines from this run."""
    return adb(serial, "shell", "date '+%m-%d %H:%M:%S.000'").strip()


def app_log_since(serial: str, since: str) -> str:
    return adb(serial, "logcat", "-d", "-T", since, "-s", LOG_TAG)


def wait_outcome(serial: str, since: str, seconds: float) -> tuple[str, str] | None:
    deadline = time.monotonic() + seconds
    while True:
        outcome = capture_outcome(app_log_since(serial, since))
        if outcome or time.monotonic() >= deadline:
            return outcome
        time.sleep(POLL_SECONDS)


def remote_size(serial: str, path: str) -> int:
    out = adb(serial, "shell", f"stat -c %s {shlex.quote(path)} 2>/dev/null || echo -1").strip()
    return int(out) if out.lstrip("-").isdigit() else -1


# --- commands ---------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    apps = [a.strip() for a in args.app.split(",") if a.strip()]
    since = device_now(args.serial)
    adb_shell(args.serial, build_start_args(apps, args.name))

    outcome = wait_outcome(args.serial, since, OUTCOME_WAIT_SECONDS)
    if outcome is None:
        # Normal path whenever another app took the VPN since the last capture.
        input("请在手机上点 VPN 授权（确定），点完按回车 >>> ")
        outcome = wait_outcome(args.serial, since, OUTCOME_WAIT_SECONDS)

    if outcome is None or outcome[0] != "started":
        print("抓包没有开始。TunPcap 日志：", file=sys.stderr)
        print(app_log_since(args.serial, since), file=sys.stderr)
        return 1
    print(outcome[1])
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    adb_shell(args.serial, build_stop_args())
    print("stop requested")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    remote = f"{PHONE_DIR}/{args.name}"
    # The app writes <name>.part and renames it only after the pcap is flushed on
    # stop, so the final name existing means the file is complete.
    deadline = time.monotonic() + PULL_WAIT_SECONDS
    while remote_size(args.serial, remote) < 24:
        if time.monotonic() >= deadline:
            print(f"{remote} 还没出现：抓包是否已 stop？（未完成的文件叫 {args.name}.part）", file=sys.stderr)
            return 1
        time.sleep(POLL_SECONDS)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    local = out_dir / args.name
    adb(args.serial, "pull", remote, str(local), timeout=600)
    with local.open("rb") as f:
        check_pcap_header(f.read(24))
    print(f"pulled {local} ({local.stat().st_size} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="TunPcap capture control over adb")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start")
    s.add_argument("--serial", required=True)
    s.add_argument("--app", required=True, help="package name(s), comma separated")
    s.add_argument("--name", help="pcap file name on the phone")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("stop")
    s.add_argument("--serial", required=True)
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("pull")
    s.add_argument("--serial", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_pull)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
