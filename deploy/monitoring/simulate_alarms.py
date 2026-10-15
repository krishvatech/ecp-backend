#!/usr/bin/env python3
"""Development test runner for the background health alarms (B14).

Runs ``publish_background_health --dry-run`` once per period (no AWS), feeds
the metric data to an in-process model of the CloudWatch alarms defined in
background-health-alerting.yaml, and prints a line for every alarm state
change - the only moments CloudWatch would notify SNS. Nothing is published
and nothing is sent.

    python deploy/monitoring/simulate_alarms.py --period 5 --ticks 40 \
        --command "../venv/bin/python manage.py publish_background_health --dry-run"

With ``--period 5`` "3 consecutive minutes" means 3 consecutive 5-second
periods. A run that exits 4, times out or prints no JSON contributes no
sample, exactly as a failed SSM invocation would.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone

COMPONENTS = ("celery_beat", "scheduled_tasks", "celery_worker", "redis_broker", "mautic_cron", "mautic_worker")


class Alarm:
    """CloudWatch alarm evaluation: ``datapoints`` breaching out of the last
    ``periods`` periods alarms; a missing period counts per TreatMissingData (ignore or breaching)."""

    def __init__(self, name, periods, datapoints, missing="ignore"):
        self.name = name
        self.periods = periods
        self.datapoints = datapoints
        self.missing = missing
        self.window = deque(maxlen=periods)
        self.state = "INSUFFICIENT_DATA"

    def evaluate(self, breaching):
        """``breaching`` is True, False or None (no data). Returns the new
        state when it changed, else None."""
        self.window.append(breaching)
        if self.missing == "breaching":
            values = [True if value is None else value for value in self.window]
        else:
            values = [value for value in self.window if value is not None]
        if breaching is None and self.missing == "ignore":
            # TreatMissingData=ignore: the current state is kept.
            new = self.state
        elif not values:
            new = "INSUFFICIENT_DATA"
        elif sum(values) >= self.datapoints:
            new = "ALARM"
        else:
            new = "OK"
        if new == self.state:
            return None
        self.state = new
        return new


def build_alarms(args):
    alarms = {"monitor-missing": Alarm("monitor-missing", args.missing, args.missing, missing="breaching")}
    for component in COMPONENTS:
        alarms[f"{component}-unhealthy"] = Alarm(f"{component}-unhealthy", args.unhealthy, args.unhealthy)
    alarms["any-warning"] = Alarm("any-warning", args.warning, args.warning)
    alarms["any-unknown"] = Alarm("any-unknown", args.unknown, args.unknown)
    return alarms


def sample(command, timeout):
    """One monitor run: (output dict or None, exit code or reason)."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if completed.returncode not in (0, 1, 2, 3) or not lines:
        return None, completed.returncode
    try:
        return json.loads(lines[-1]), completed.returncode
    except json.JSONDecodeError:
        return None, "bad-json"


def flags(output):
    """Per-alarm breaching flags from one run: its metric data (--dry-run),
    else the component statuses it printed after publishing."""
    if not output.get("metric_data"):
        statuses = {key: (value or {}).get("status") for key, value in (output.get("components") or {}).items()}
        result = {"monitor-missing": False}
        for component in COMPONENTS:
            result[f"{component}-unhealthy"] = statuses.get(component) == "Unhealthy"
        result["any-warning"] = any(statuses.get(c) in ("Warning", "Unhealthy") for c in COMPONENTS)
        result["any-unknown"] = any(statuses.get(c, "Unknown") == "Unknown" for c in COMPONENTS)
        return result
    by_metric = {}
    for item in output.get("metric_data") or []:
        component = next((d["Value"] for d in item["Dimensions"] if d["Name"] == "Component"), None)
        by_metric.setdefault(item["MetricName"], {})[component] = item["Value"] >= 1
    result = {"monitor-missing": False}
    for component in COMPONENTS:
        result[f"{component}-unhealthy"] = by_metric.get("ComponentUnhealthy", {}).get(component, False)
    result["any-warning"] = any(by_metric.get("ComponentDegraded", {}).values())
    result["any-unknown"] = any(by_metric.get("ComponentUnknown", {}).values())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--command", required=True, help="dry-run monitor command (must print metric_data)")
    parser.add_argument("--period", type=float, default=60, help="seconds per evaluation period")
    parser.add_argument("--ticks", type=int, default=0, help="stop after N periods (0 = run until Ctrl-C)")
    parser.add_argument("--timeout", type=float, default=100, help="seconds before a run counts as failed")
    parser.add_argument("--unhealthy", type=int, default=3)
    parser.add_argument("--warning", type=int, default=10)
    parser.add_argument("--unknown", type=int, default=15)
    parser.add_argument("--missing", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="print transitions as JSON lines")
    args = parser.parse_args(argv)

    command = shlex.split(args.command)
    alarms = build_alarms(args)
    tick = 0
    try:
        while not args.ticks or tick < args.ticks:
            started = time.monotonic()
            tick += 1
            output, code = sample(command, args.timeout)
            current = flags(output) if output else {name: None for name in alarms}
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            status = output.get("status") if output else f"no sample ({code})"
            print(f"[{now}] tick {tick} exit={code} status={status}", flush=True)
            for name, alarm in alarms.items():
                changed = alarm.evaluate(current[name])
                if changed:
                    record = {"tick": tick, "at": now, "alarm": name, "state": changed}
                    print(json.dumps(record) if args.json else f"[{now}]   >> {name}: {changed}", flush=True)
            elapsed = time.monotonic() - started
            if not args.ticks or tick < args.ticks:
                time.sleep(max(0.0, args.period - elapsed))
    except KeyboardInterrupt:
        pass
    print("final: " + ", ".join(f"{name}={alarm.state}" for name, alarm in alarms.items()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
