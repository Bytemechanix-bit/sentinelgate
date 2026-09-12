"""PCI DSS control/evidence mapping for SentinelGate policies."""
from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .rules import Policy

PCI_DSS_REQUIREMENTS = {
    "1.2.1": "Restrict inbound/outbound traffic to that which is necessary",
    "1.2.5": "Identify and justify permitted services, protocols, and ports",
    "1.3.1": "Restrict inbound traffic to the CDE",
    "1.3.2": "Restrict outbound traffic from the CDE",
    "1.4.1": "Implement network security controls between trusted and untrusted networks",
    "10.2.1": "Capture individual access to system components in audit logs",
}


def generate_report(policy: Policy) -> str:
    policy.validate()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# PCI DSS Control Evidence — {policy.name}",
        f"_Generated {now} by SentinelGate v{__version__}_",
        "",
        "> This is an audit-support artifact. It maps declared policy controls to PCI DSS references; it does not establish compliance or replace a qualified assessment.",
        "",
        "## Assessment snapshot",
        f"- Policy validation: **PASS**",
        f"- Default posture: **{policy.default_action.value.upper()}**",
        f"- Rules: **{len(policy.rules)}**",
        f"- Rules with PCI DSS references: **{sum(bool(r.pci_dss_ref) for r in policy.rules)}/{len(policy.rules)}**",
        "",
        "## Rule evidence",
        "",
        "| Priority | Rule | Action | Source | Destination | Port | PCI DSS | Justification |",
        "|---:|---|---|---|---|---|---|---|",
    ]
    unmapped = []
    for r in policy.ordered_rules():
        ref = r.pci_dss_ref or "—"
        if not r.pci_dss_ref:
            unmapped.append(r.name)
        lines.append(
            f"| {r.priority} | {r.name} | {r.action.value} | {r.src} | {r.dst} | "
            f"{r.dst_port or 'any'} | {ref} | {r.comment} |"
        )

    lines += ["", "## Requirement reference", ""]
    for ref, desc in PCI_DSS_REQUIREMENTS.items():
        lines.append(f"- **{ref}** — {desc}")

    if unmapped:
        lines += [
            "", "## Review required",
            "The following rules have no PCI DSS reference and should be reviewed by the control owner:",
            *[f"- {name}" for name in unmapped],
        ]
    else:
        lines += ["", "## Mapping completeness", "All declared rules have a PCI DSS reference."]
    return "\n".join(lines)
