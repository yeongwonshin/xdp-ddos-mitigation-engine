#!/usr/bin/env python3
"""Control plane for the defensive XDP DDoS mitigation engine.

The CLI intentionally uses bpftool subprocesses instead of sending packets or
opening raw sockets. It updates pinned BPF maps that are created by the XDP
program loader/attachment step.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List

PIN_ROOT = Path("/sys/fs/bpf/xdp_ddos")
MAPS = {
    "config": PIN_ROOT / "config_map",
    "allow": PIN_ROOT / "allowlist_map",
    "block": PIN_ROOT / "blocklist_map",
    "reputation": PIN_ROOT / "reputation_map",
    "stats": PIN_ROOT / "stats_map",
}

STAT_NAMES = {
    0: "pass",
    1: "drop_blocklist",
    2: "drop_reputation",
    3: "drop_syn_rate",
    4: "drop_udp_rate",
    5: "drop_icmp_rate",
    6: "drop_malformed",
}


def require_bpftool() -> None:
    if not shutil.which("bpftool"):
        raise SystemExit("bpftool not found. Install bpftool or run this CLI on the target host.")


def run(cmd: List[str], *, capture: bool = False) -> str:
    require_bpftool()
    try:
        result = subprocess.run(cmd, check=True, text=True, capture_output=capture)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr or exc.stdout or str(exc), file=sys.stderr)
        raise SystemExit(exc.returncode)
    return result.stdout if capture else ""


def bytes_to_hex_args(data: bytes) -> List[str]:
    return [f"{b:02x}" for b in data]


def ip_key(ip: str) -> List[str]:
    # XDP stores iph->saddr as the raw packet bytes, so use network byte order.
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        raise SystemExit("Only IPv4 is supported in this project version.")
    return bytes_to_hex_args(addr.packed)


def u8_value(v: int = 1) -> List[str]:
    return [f"{v & 0xff:02x}"]


def config_value(policy: dict) -> List[str]:
    fields = [
        int(policy.get("syn_pps_limit", 2000)),
        int(policy.get("udp_pps_limit", 5000)),
        int(policy.get("icmp_pps_limit", 1000)),
        int(policy.get("reputation_drop_score", 80)),
        int(policy.get("allowlist_enabled", True)),
        int(policy.get("blocklist_enabled", True)),
        int(policy.get("reputation_enabled", True)),
        int(policy.get("audit_only", True)),
    ]
    return bytes_to_hex_args(struct.pack("<8I", *fields))


def reputation_value(score: int) -> List[str]:
    if score < 0 or score > 100:
        raise SystemExit("reputation score must be between 0 and 100")
    # struct reputation_value { __u32 score; __u64 updated_ns; }
    # updated_ns is maintained as metadata for operators; use 0 from CLI.
    return bytes_to_hex_args(struct.pack("<I4xQ", score, 0))


def map_update(map_path: Path, key_hex: Iterable[str], value_hex: Iterable[str]) -> None:
    run(["bpftool", "map", "update", "pinned", str(map_path), "key", "hex", *key_hex, "value", "hex", *value_hex])


def map_delete(map_path: Path, key_hex: Iterable[str]) -> None:
    run(["bpftool", "map", "delete", "pinned", str(map_path), "key", "hex", *key_hex])


def map_dump(map_path: Path) -> str:
    return run(["bpftool", "-j", "map", "dump", "pinned", str(map_path)], capture=True)


def cmd_config_apply(args: argparse.Namespace) -> None:
    with open(args.file, "r", encoding="utf-8") as f:
        policy = json.load(f)
    map_update(MAPS["config"], ["00", "00", "00", "00"], config_value(policy))
    print(f"Applied policy from {args.file}")


def cmd_list_add_del(args: argparse.Namespace) -> None:
    target = MAPS[args.list_name]
    key = ip_key(args.ip)
    if args.action == "add":
        map_update(target, key, u8_value(1))
        print(f"Added {args.ip} to {args.list_name}list")
    elif args.action == "del":
        map_delete(target, key)
        print(f"Removed {args.ip} from {args.list_name}list")
    else:
        raise SystemExit(f"Unsupported action: {args.action}")


def cmd_list_dump(args: argparse.Namespace) -> None:
    print(map_dump(MAPS[args.list_name]))


def cmd_reputation_set(args: argparse.Namespace) -> None:
    map_update(MAPS["reputation"], ip_key(args.ip), reputation_value(args.score))
    print(f"Set reputation score for {args.ip} to {args.score}")


def cmd_stats(_: argparse.Namespace) -> None:
    print("Raw per-CPU stats map dump. Sum per-CPU values when multiple CPUs are shown:")
    print(map_dump(MAPS["stats"]))


def cmd_paths(_: argparse.Namespace) -> None:
    print(json.dumps({k: str(v) for k, v in MAPS.items()}, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive XDP DDoS mitigation control plane")
    sub = parser.add_subparsers(required=True)

    paths = sub.add_parser("paths", help="show pinned map paths")
    paths.set_defaults(func=cmd_paths)

    stats = sub.add_parser("stats", help="dump stats map")
    stats.set_defaults(func=cmd_stats)

    cfg = sub.add_parser("config", help="manage runtime policy config")
    cfg_sub = cfg.add_subparsers(required=True)
    cfg_apply = cfg_sub.add_parser("apply", help="apply policy JSON to config map")
    cfg_apply.add_argument("--file", required=True)
    cfg_apply.set_defaults(func=cmd_config_apply)

    for name in ("allow", "block"):
        lp = sub.add_parser(name, help=f"manage {name}list")
        lp_sub = lp.add_subparsers(required=True)
        add = lp_sub.add_parser("add")
        add.add_argument("ip")
        add.set_defaults(func=cmd_list_add_del, list_name=name, action="add")
        delete = lp_sub.add_parser("del")
        delete.add_argument("ip")
        delete.set_defaults(func=cmd_list_add_del, list_name=name, action="del")
        dump = lp_sub.add_parser("dump")
        dump.set_defaults(func=cmd_list_dump, list_name=name)

    rep = sub.add_parser("reputation", help="manage reputation scores")
    rep_sub = rep.add_subparsers(required=True)
    rep_set = rep_sub.add_parser("set")
    rep_set.add_argument("ip")
    rep_set.add_argument("--score", type=int, required=True)
    rep_set.set_defaults(func=cmd_reputation_set)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
