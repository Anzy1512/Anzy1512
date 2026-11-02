"""Offline authentication event detector. Standard-library only; synthetic demo input."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
import json


class EventError(ValueError):
    """An input record failed schema validation."""


def parse_event(raw: dict[str, Any], line: int = 0) -> dict[str, Any]:
    required = ("timestamp", "host", "user", "src_ip", "event_type", "outcome")
    if not isinstance(raw, dict):
        raise EventError(f"line {line}: expected JSON object")
    if any(not isinstance(raw.get(key), str) or not raw[key].strip() for key in required):
        raise EventError(f"line {line}: required string fields: {', '.join(required)}")
    if raw["event_type"] != "authentication" or raw["outcome"] not in ("success", "failure"):
        raise EventError(f"line {line}: unsupported event_type/outcome")
    try:
        timestamp = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timezone required")
        timestamp = timestamp.astimezone(timezone.utc)
        ip_address(raw["src_ip"])
    except ValueError as exc:
        raise EventError(f"line {line}: invalid timestamp or source IP: {exc}") from exc
    return {**{key: raw[key] for key in required}, "_dt": timestamp}


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if line.strip():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EventError(f"line {line_no}: invalid JSON: {exc.msg}") from exc
                events.append(parse_event(data, line_no))
    return sorted(events, key=lambda e: e["_dt"])


def alert(rule: str, technique: str, description: str, evidence: list[dict[str, Any]],
          severity: str = "medium") -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "attack_technique": technique,
        "summary": description,
        "first_seen": evidence[0]["_dt"].isoformat(),
        "last_seen": evidence[-1]["_dt"].isoformat(),
        "event_count": len(evidence),
        "users": sorted({event["user"] for event in evidence}),
        "source_ips": sorted({event["src_ip"] for event in evidence}),
        "hosts": sorted({event["host"] for event in evidence}),
    }


def analyze(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one first-match alert per rule and grouping key, for each invocation."""
    ordered = sorted(events, key=lambda event: event["_dt"])
    failures = [event for event in ordered if event["outcome"] == "failure"]
    grouped_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    grouped_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in failures:
        grouped_pair[(event["src_ip"], event["user"])].append(event)
        grouped_ip[event["src_ip"]].append(event)

    alerts: list[dict[str, Any]] = []
    # T1110.001: five failed attempts for one source/account in five minutes.
    for (source, user), seq in sorted(grouped_pair.items()):
        for index, event in enumerate(seq):
            window = [item for item in seq[:index + 1]
                      if item["_dt"] >= event["_dt"] - timedelta(minutes=5)]
            if len(window) >= 5:
                alerts.append(alert("repeated_login_failures", "T1110.001",
                                    f"Repeated failures for {user} from {source}", window))
                break

    # T1110.003: five failures across three distinct accounts from one source in ten minutes.
    for source, seq in sorted(grouped_ip.items()):
        for index, event in enumerate(seq):
            window = [item for item in seq[:index + 1]
                      if item["_dt"] >= event["_dt"] - timedelta(minutes=10)]
            if len(window) >= 5 and len({item["user"] for item in window}) >= 3:
                alerts.append(alert("possible_password_spray", "T1110.003",
                                    f"Failures across multiple accounts from {source}", window))
                break

    # T1110.001: >=3 preceding failures for same source/user, then success within 10 minutes.
    seen_pairs: set[tuple[str, str]] = set()
    for event in ordered:
        if event["outcome"] != "success":
            continue
        key = (event["src_ip"], event["user"])
        if key in seen_pairs:
            continue
        prior = [f for f in grouped_pair.get(key, [])
                 if event["_dt"] - timedelta(minutes=10) <= f["_dt"] < event["_dt"]]
        if len(prior) >= 3:
            alerts.append(alert("success_after_failures", "T1110.001",
                                f"Successful authentication after failures for {key[1]} from {key[0]}",
                                [*prior, event], "high"))
            seen_pairs.add(key)

    return sorted(alerts, key=lambda item: (item["first_seen"], item["rule"]))
