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
VPN_SESSION = "sessionid=tunpcap"

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_RAW = 101

VPN_WAIT_SECONDS = 10
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


def vpn_active(dumpsys_connectivity: str) -> bool:
    """Same signal the PCAPdroid capture script uses: the VPN session name."""
    return VPN_SESSION in dumpsys_connectivity.lower()


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


def is_vpn_up(serial: str) -> bool:
    return vpn_active(adb(serial, "shell", "dumpsys connectivity"))


def wait_vpn(serial: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if is_vpn_up(serial):
            return True
        time.sleep(POLL_SECONDS)
    return is_vpn_up(serial)


def recent_app_log(serial: str, lines: int = 20) -> str:
    log = adb(serial, "logcat", "-d")
    hits = [line for line in log.splitlines() if "TunPcap" in line]
    return "\n".join(hits[-lines:])


def remote_size(serial: str, path: str) -> int:
    out = adb(serial, "shell", f"stat -c %s {shlex.quote(path)} 2>/dev/null || echo -1").strip()
    return int(out) if out.lstrip("-").isdigit() else -1


# --- commands ---------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    apps = [a.strip() for a in args.app.split(",") if a.strip()]
    adb_shell(args.serial, build_start_args(apps, args.name))

    if not wait_vpn(args.serial, VPN_WAIT_SECONDS):
        # Normal path whenever another app took the VPN since the last capture.
        input("请在手机上点 VPN 授权（确定），点完按回车 >>> ")
        if not wait_vpn(args.serial, VPN_WAIT_SECONDS):
            print("VPN 没有起来。TunPcap 日志：", file=sys.stderr)
            print(recent_app_log(args.serial), file=sys.stderr)
            return 1
    print(f"capturing {','.join(apps)} → {PHONE_DIR}/{args.name or '<default name, see logcat>'}")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    adb_shell(args.serial, build_stop_args())
    print("stop requested")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    remote = f"{PHONE_DIR}/{args.name}"
    # The app flushes on stop; wait until the size settles before pulling.
    last = -1
    for _ in range(60):
        size = remote_size(args.serial, remote)
        if size >= 24 and size == last:
            break
        last = size
        time.sleep(POLL_SECONDS)
    else:
        print(f"{remote} 不存在或一直在变大 (size={last})", file=sys.stderr)
        return 1

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
