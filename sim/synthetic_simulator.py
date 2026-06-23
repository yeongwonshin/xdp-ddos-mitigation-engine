#!/usr/bin/env python3
"""Safe synthetic policy simulator for the XDP DDoS mitigation engine.

This simulator does NOT send packets, open sockets, use raw sockets, or replay
traffic. It generates in-memory flow events so defenders can tune thresholds and
validate allowlist/blocklist/reputation behavior.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

TCP_SYN = "tcp_syn"
UDP = "udp"
ICMP = "icmp"
NORMAL = "normal"


@dataclass(frozen=True)
class Event:
    ts_ms: int
    src_ip: str
    proto: str
    dst_port: int = 0


@dataclass
class Policy:
    syn_pps_limit: int = 2000
    udp_pps_limit: int = 5000
    icmp_pps_limit: int = 1000
    reputation_drop_score: int = 80
    allowlist_enabled: bool = True
    blocklist_enabled: bool = True
    reputation_enabled: bool = True
    audit_only: bool = False


class DefensivePolicyEngine:
    def __init__(
        self,
        policy: Optional[Policy] = None,
        allowlist: Optional[Iterable[str]] = None,
        blocklist: Optional[Iterable[str]] = None,
        reputation: Optional[Dict[str, int]] = None,
    ) -> None:
        self.policy = policy or Policy()
        self.allowlist = set(allowlist or [])
        self.blocklist = set(blocklist or [])
        self.reputation = dict(reputation or {})
        self.windows: Dict[Tuple[str, str, int], Tuple[int, int]] = {}
        self.stats: Counter[str] = Counter()

    def _limit_for(self, proto: str) -> int:
        if proto == TCP_SYN:
            return self.policy.syn_pps_limit
        if proto == UDP:
            return self.policy.udp_pps_limit
        if proto == ICMP:
            return self.policy.icmp_pps_limit
        return 0

    def evaluate(self, event: Event) -> str:
        """Return PASS, DROP:<reason>, or AUDIT:<reason>."""
        if self.policy.allowlist_enabled and event.src_ip in self.allowlist:
            self.stats["pass"] += 1
            return "PASS"

        if self.policy.blocklist_enabled and event.src_ip in self.blocklist:
            return self._drop("blocklist")

        if self.policy.reputation_enabled and self.reputation.get(event.src_ip, 0) >= self.policy.reputation_drop_score:
            return self._drop("reputation")

        limit = self._limit_for(event.proto)
        if limit:
            key = (event.src_ip, event.proto, event.dst_port)
            window_start_ms, count = self.windows.get(key, (event.ts_ms, 0))
            if event.ts_ms - window_start_ms >= 1000:
                window_start_ms, count = event.ts_ms, 0
            count += 1
            self.windows[key] = (window_start_ms, count)
            if count > limit:
                return self._drop(f"{event.proto}_rate")

        self.stats["pass"] += 1
        return "PASS"

    def _drop(self, reason: str) -> str:
        if self.policy.audit_only:
            self.stats[f"audit_{reason}"] += 1
            return f"AUDIT:{reason}"
        self.stats[f"drop_{reason}"] += 1
        return f"DROP:{reason}"


def synthetic_sources(count: int, base: str = "198.51.100.0") -> List[str]:
    network = ipaddress.ip_network(f"{base}/24", strict=False)
    usable = [str(ip) for ip in network.hosts()]
    if count > len(usable):
        raise ValueError("src-count exceeds /24 synthetic source pool")
    return usable[:count]


def generate_events(scenario: str, pps: int, duration: int, src_count: int, seed: int = 7) -> List[Event]:
    random.seed(seed)
    sources = synthetic_sources(src_count)
    total = pps * duration
    events: List[Event] = []
    interval_ms = 1000 / max(pps, 1)

    for i in range(total):
        ts_ms = int(i * interval_ms)
        src_ip = sources[i % src_count]
        if scenario == "syn":
            proto, port = TCP_SYN, 443
        elif scenario == "udp":
            proto, port = UDP, 53
        elif scenario == "icmp":
            proto, port = ICMP, 0
        elif scenario == "mixed":
            proto = random.choices([TCP_SYN, UDP, ICMP, NORMAL], weights=[35, 35, 20, 10])[0]
            port = 443 if proto == TCP_SYN else 53 if proto == UDP else 0
        elif scenario == "normal":
            proto = random.choices([TCP_SYN, UDP, ICMP, NORMAL], weights=[5, 25, 5, 65])[0]
            port = 443 if proto == TCP_SYN else 123 if proto == UDP else 0
        else:
            raise ValueError(f"unknown scenario: {scenario}")
        events.append(Event(ts_ms=ts_ms, src_ip=src_ip, proto=proto, dst_port=port))
    return events


def run_simulation(args: argparse.Namespace) -> dict:
    policy = Policy(
        syn_pps_limit=args.syn_limit,
        udp_pps_limit=args.udp_limit,
        icmp_pps_limit=args.icmp_limit,
        reputation_drop_score=args.reputation_drop_score,
        audit_only=args.audit_only,
    )
    sources = synthetic_sources(args.src_count)
    reputation = {}
    blocklist = set()
    allowlist = set()

    if args.reputation_first_n:
        for ip in sources[: args.reputation_first_n]:
            reputation[ip] = args.reputation_score
    if args.block_first_n:
        blocklist.update(sources[: args.block_first_n])
    if args.allow_first_n:
        allowlist.update(sources[: args.allow_first_n])

    engine = DefensivePolicyEngine(policy, allowlist=allowlist, blocklist=blocklist, reputation=reputation)
    decisions = Counter()
    for event in generate_events(args.scenario, args.pps, args.duration, args.src_count, args.seed):
        decisions[engine.evaluate(event)] += 1

    return {
        "scenario": args.scenario,
        "pps": args.pps,
        "duration_seconds": args.duration,
        "src_count": args.src_count,
        "policy": policy.__dict__,
        "decisions": dict(decisions),
        "stats": dict(engine.stats),
        "safety": "synthetic-only: no network packets were generated or transmitted",
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Safe synthetic simulator for defensive XDP DDoS policy tuning")
    p.add_argument("--scenario", choices=["syn", "udp", "icmp", "mixed", "normal"], default="syn")
    p.add_argument("--pps", type=int, default=10000)
    p.add_argument("--duration", type=int, default=3)
    p.add_argument("--src-count", type=int, default=100)
    p.add_argument("--syn-limit", type=int, default=2000)
    p.add_argument("--udp-limit", type=int, default=5000)
    p.add_argument("--icmp-limit", type=int, default=1000)
    p.add_argument("--reputation-drop-score", type=int, default=80)
    p.add_argument("--reputation-first-n", type=int, default=0)
    p.add_argument("--reputation-score", type=int, default=90)
    p.add_argument("--block-first-n", type=int, default=0)
    p.add_argument("--allow-first-n", type=int, default=0)
    p.add_argument("--audit-only", action="store_true")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--json", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    result = run_simulation(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Synthetic simulation summary")
        print("----------------------------")
        for k in ("scenario", "pps", "duration_seconds", "src_count", "safety"):
            print(f"{k}: {result[k]}")
        print("decisions:")
        for decision, count in sorted(result["decisions"].items()):
            print(f"  {decision}: {count}")


if __name__ == "__main__":
    main()
