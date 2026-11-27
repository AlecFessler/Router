#!/usr/bin/env python3
"""Display an oracle run in the terminal. Run from the oracle's output directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time


def latest_run(directory):
    return max(directory.glob("*/summary.json"), key=lambda path: path.parent.stat().st_mtime,
               default=None)


def examples(path, limit):
    lines = []
    try:
        with path.open() as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if (row["unhandled"] or row["error"] or row["comparison"] in ("forwarded_differently", "answered_differently")
                        or row["comparison"].startswith(("google_forwarded_shadow_", "google_answered_shadow_"))):
                    lines.append(row)
    except FileNotFoundError:
        return []
    return lines[-limit:]


def render(path):
    snapshot = json.loads(path.read_text())
    age = max(0, time.time() - snapshot["updated_at"])
    counts = snapshot["counts"]
    rows = [
        f"Router readiness   {path.parent.name}   {snapshot['status']}   updated {age:.0f}s ago",
        "",
        f"Capture frames     LAN {counts.get('lan_frames', 0):,}   "
        f"WAN in {counts.get('wan-in_frames', 0):,}   WAN out {counts.get('wan-out_frames', 0):,}",
        f"LAN feed           {snapshot.get('lan_feed', 'seen' if counts.get('lan_frames') else 'waiting')}",
        f"Shadow ingress     LAN {counts.get('lan_input', 0):,}   "
        f"WAN {counts.get('wan_input', 0):,}   Pending {snapshot['pending']:,}",
        "",
        "Comparison",
    ]
    groups = {
        "Both forwarded": counts.get("both_forwarded", 0),
        "Both answered locally": counts.get("both_answered", 0),
        "Google forwarded, shadow dropped": counts.get("google_forwarded_shadow_dropped", 0),
        "Google forwarded, no shadow NAT map": counts.get("google_forwarded_shadow_no_mapping", 0),
        "Google forwarded, shadow answered": counts.get("google_forwarded_shadow_answered", 0),
        "Forwarded differently": counts.get("forwarded_differently", 0),
        "Answered differently": counts.get("answered_differently", 0),
        "Shadow forwarded, Google likely dropped": counts.get("shadow_forwarded_google_likely_dropped", 0),
        "Shadow forwarded, Google unobserved": counts.get("shadow_forwarded_google_unobserved", 0),
        "Unhandled": counts.get("unhandled", 0),
        "Handler errors on scoped traffic": counts.get("handler_error_scoped", 0),
    }
    rows.extend(f"  {name:<41} {count:>10,}" for name, count in groups.items())
    if "lan_both_forwarded" in counts or "wan_both_forwarded" in counts:
        rows.append(f"  Forwarding matches   LAN→WAN {counts.get('lan_both_forwarded', 0):,}   "
                    f"WAN→LAN {counts.get('wan_both_forwarded', 0):,}")
    details = {
        "WAN traffic outside tracked flows": counts.get("unscoped_wan", counts.get("inconclusive_nat_state", 0)),
        "Background WAN handler errors": counts.get("handler_error_unscoped_wan", 0),
        "Google LAN forward, original NAT unknown": counts.get("google_forwarded_nat_state_unknown", 0),
    }
    details.update({key.removeprefix("inconclusive_").replace("_", " "): n for key, n in counts.items()
                    if key.startswith("inconclusive_") and key != "inconclusive_nat_state"})
    rows.extend(("", "Coverage and inconclusive cases"))
    rows.extend(f"  {name:<41} {count:>10,}" for name, count in details.items())
    health = {key: n for key, n in counts.items() if key.endswith(
        ("_clock_or_lag", "_queue_drops", "_truncated", "_limit", "_disconnected", "_offload",
         "_clock_uncertain", "_clock_step", "_kernel_drops")
    ) or key == "wan_address_changed"}
    if health:
        rows.extend(("", "Capture health"))
        rows.extend(f"  {key.replace('_', ' '):<41} {count:>10,}" for key, count in sorted(health.items()))
    samples = examples(path.parent / "examples.jsonl", 5)
    if samples:
        rows.extend(("", "Recent retained examples"))
        for item in samples:
            label = item["error"] or ("unhandled" if item["unhandled"] else item["comparison"])
            protocol = (f"IPv4 protocol {item['protocol']}" if item["ethertype"] == "0x0800"
                        else f"EtherType {item['ethertype']}")
            rows.append(f"  #{item['id']} {item['ingress'].upper()} {label}  {protocol}")
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, nargs="?", help="run directory, defaults to the latest run")
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("interval must be positive")
    try:
        path = args.run / "summary.json" if args.run else None
        while True:
            if path is None:
                path = latest_run(Path.cwd())
            view = render(path) if path and path.exists() else "Waiting for an oracle run…\n"
            if sys.stdout.isatty() and not args.once:
                print("\x1b[H\x1b[J", end="")
            print(view, end="", flush=True)
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
