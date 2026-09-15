"""SentinelGate CLI."""
from __future__ import annotations

import json
import os

import click

from .change_control import (
    append_audit,
    detect_conflicts,
    verify_approval,
    write_approval,
)
from .compliance import generate_report
from .engine import FirewallEngine
from .rules import Packet, Policy


@click.group()
@click.version_option()
def main():
    """Policy-as-code firewall engine with simulation and compliance evidence."""


@main.command()
@click.argument("policy_file")
@click.option("--fail-on-conflict", is_flag=True)
def validate(policy_file: str, fail_on_conflict: bool):
    """Validate a policy and optionally fail on ambiguous conflicts."""
    policy = Policy.from_yaml(policy_file)
    conflicts = detect_conflicts(policy)
    if conflicts:
        for item in conflicts:
            click.echo(f"Conflict: {item['first_rule']} vs {item['second_rule']} — {item['reason']}", err=True)
        if fail_on_conflict:
            raise click.ClickException("policy contains conflicting rules")
    click.echo(click.style(f"Valid policy: {policy.name} ({len(policy.rules)} rules)", fg="green"))


@main.command()
@click.argument("policy_file")
def conflicts(policy_file: str):
    """Report ambiguous overlapping rules."""
    found = detect_conflicts(Policy.from_yaml(policy_file))
    if not found:
        click.echo("No conflicting rules detected.")
        return
    for item in found:
        click.echo(f"{item['first_rule']} <-> {item['second_rule']}: {item['reason']}")


@main.command()
@click.argument("policy_file")
def render(policy_file: str):
    """Render policy as nftables."""
    click.echo(Policy.from_yaml(policy_file).to_nftables())


@main.command()
@click.argument("policy_file")
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON.")
@click.option("--audit-log", type=click.Path(dir_okay=False), help="Write timestamped JSON-lines audit events.")
def simulate(policy_file: str, json_output: bool, audit_log: str | None):
    """Run representative traffic through the policy."""
    engine = FirewallEngine(Policy.from_yaml(policy_file))
    packets = [
        Packet("203.0.113.10", "10.0.0.5", "tcp", 22, 50001),
        Packet("198.51.100.7", "10.0.0.5", "tcp", 443, 50002),
        Packet("10.0.0.5", "8.8.8.8", "udp", 53, 53000),
        Packet("185.220.101.5", "10.0.0.5", "tcp", 3389, 40000),
        Packet("192.0.2.200", "10.0.0.5", "tcp", 80, 40001),
    ]
    verdicts = engine.simulate(packets)
    if audit_log:
        for verdict in verdicts:
            append_audit(audit_log, "packet_decision", action=verdict.action.value,
                         matched_rule=verdict.matched_rule, reason=verdict.reason,
                         source=verdict.packet.src_ip, destination=verdict.packet.dst_ip,
                         protocol=verdict.packet.protocol, destination_port=verdict.packet.dst_port)
    if json_output:
        click.echo(json.dumps([{
            "source": v.packet.src_ip, "destination": v.packet.dst_ip,
            "protocol": v.packet.protocol, "destination_port": v.packet.dst_port,
            "action": v.action.value, "matched_rule": v.matched_rule, "reason": v.reason,
        } for v in verdicts], indent=2))
        return
    for v in verdicts:
        colour = "green" if v.action.value == "allow" else "red"
        click.echo(click.style(
            f"[{v.action.value.upper():5}] {v.packet.src_ip:>15} -> {v.packet.dst_ip}:{v.packet.dst_port}/{v.packet.protocol}"
            f"  ({v.matched_rule}: {v.reason})", fg=colour))


@main.command()
@click.argument("policy_file")
def report(policy_file: str):
    """Generate PCI DSS control-mapping evidence in Markdown."""
    click.echo(generate_report(Policy.from_yaml(policy_file)))


@main.command()
@click.argument("policy_file")
@click.option("--approver", required=True)
@click.option("--approval-dir", default=".sentinelgate/approvals", show_default=True, type=click.Path(file_okay=False))
def approve(policy_file: str, approver: str, approval_dir: str):
    """Create an approval record bound to the current policy hash."""
    path = write_approval(policy_file, approver, approval_dir)
    click.echo(click.style(f"Approval recorded: {path}", fg="green"))


@main.command()
@click.argument("policy_file")
@click.option("--ruleset-path", default="/etc/sentinelgate/ruleset.nft", show_default=True)
@click.option("--approval", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--requester", default=lambda: os.getenv("SENTINELGATE_REQUESTER", ""), show_default="env SENTINELGATE_REQUESTER")
@click.option("--audit-log", default="/var/log/sentinelgate/audit.jsonl", show_default=True, type=click.Path(dir_okay=False))
@click.option("--yes", is_flag=True, help="Confirm live firewall replacement.")
def apply(policy_file: str, ruleset_path: str, approval: str, requester: str, audit_log: str, yes: bool):
    """Verify approval and apply the policy to nftables (destructive)."""
    if not yes:
        raise click.UsageError("Live apply replaces the active nftables ruleset. Re-run with --yes after reviewing 'sentinelgate render'.")
    policy = Policy.from_yaml(policy_file)
    if detect_conflicts(policy):
        raise click.ClickException("conflicting rules detected; resolve them before deployment")
    try:
        approval_record = verify_approval(policy_file, approval, requester or None)
    except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc
    FirewallEngine(policy).apply_live(ruleset_path)
    append_audit(audit_log, "firewall_apply", approver=approval_record["approver"],
                 policy_sha256=approval_record["policy_sha256"], ruleset=ruleset_path)
    click.echo(click.style("Ruleset validated, approval verified, and applied.", fg="green"))
