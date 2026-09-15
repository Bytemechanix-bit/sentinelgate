"""Policy conflict detection, audit logging, and deployment approvals."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from .rules import Policy, Protocol, Rule


def _networks(value: str) -> list[ipaddress._BaseNetwork] | None:
    if value.strip().lower() == "any":
        return None
    return [ipaddress.ip_network(item.strip(), strict=False) for item in value.split(",")]


def _overlap(first: str, second: str) -> bool:
    a, b = _networks(first), _networks(second)
    if a is None or b is None:
        return True
    return any(x.version == y.version and x.overlaps(y) for x in a for y in b)


def _ports(value: str | None) -> set[int] | None:
    if not value:
        return None
    result: set[int] = set()
    for item in value.split(","):
        part = item.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            result.update(range(lo, hi + 1))
        else:
            result.add(int(part))
    return result


def _port_overlap(first: str | None, second: str | None) -> bool:
    a, b = _ports(first), _ports(second)
    return a is None or b is None or bool(a & b)


def _protocol_overlap(first: Rule, second: Rule) -> bool:
    return first.protocol == Protocol.ANY or second.protocol == Protocol.ANY or first.protocol == second.protocol


def detect_conflicts(policy: Policy) -> list[dict[str, str]]:
    """Find ambiguous overlapping rules with the same priority and different actions."""
    result: list[dict[str, str]] = []
    rules = policy.ordered_rules()
    for index, first in enumerate(rules):
        for second in rules[index + 1:]:
            if first.priority != second.priority or first.action == second.action:
                continue
            if not _protocol_overlap(first, second):
                continue
            if not _overlap(first.src, second.src) or not _overlap(first.dst, second.dst):
                continue
            if not _port_overlap(first.dst_port, second.dst_port):
                continue
            result.append({
                "first_rule": first.name,
                "second_rule": second.name,
                "winner": min(first.name, second.name),
                "reason": "same-priority rules overlap but have different actions",
            })
    return result


def policy_digest(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_approval(policy_path: str | Path, approver: str, approval_dir: str | Path) -> Path:
    if not approver.strip():
        raise ValueError("approver cannot be empty")
    destination = Path(approval_dir) / (Path(policy_path).stem + ".json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({
        "policy_sha256": policy_digest(policy_path),
        "approver": approver.strip(),
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2) + "\n", encoding="utf-8")
    return destination


def verify_approval(policy_path: str | Path, approval_path: str | Path, requester: str | None) -> dict:
    record = json.loads(Path(approval_path).read_text(encoding="utf-8"))
    if record.get("policy_sha256") != policy_digest(policy_path):
        raise PermissionError("approval does not match the current policy; approval must be renewed")
    approver = str(record.get("approver", "")).strip()
    if not approver:
        raise PermissionError("approval record has no approver")
    if requester and requester.strip().casefold() == approver.casefold():
        raise PermissionError("separation of duties violation: requester cannot approve their own change")
    return record


def append_audit(path: str | Path, event: str, **fields: object) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
