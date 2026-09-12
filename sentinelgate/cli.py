"""SentinelGate CLI."""
from __future__ import annotations

import json

import click

from .compliance import generate_report
from .engine import FirewallEngine
from .rules import Packet, Policy


@click.group()
@click.version_option()
def main():
    """Policy-as-code firewall engine with simulation and compliance evidence."""


@main.command()
@click.argument("policy_file")
def validate(policy_file: str):
    """Validate a policy without rendering or applying it."""
    policy = Policy.from_yaml(policy_file)
    click.echo(click.style(f"Valid policy: {policy.name} ({len(policy.rules)} rules)", fg="green"))


@main.command()
@click.argument("policy_file")
def render(policy_file: str):
    """Render policy as nftables."""
    click.echo(Policy.from_yaml(policy_file).to_nftables())


@main.command()
@click.argument("policy_file")
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON.")
def simulate(policy_file: str, json_output: bool):
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
@click.option("--ruleset-path", default="/etc/sentinelgate/ruleset.nft", show_default=True)
@click.option("--yes", is_flag=True, help="Confirm live firewall replacement.")
def apply(policy_file: str, ruleset_path: str, yes: bool):
    """Validate and apply the policy to nftables (destructive)."""
    if not yes:
        raise click.UsageError("Live apply replaces the active nftables ruleset. Re-run with --yes after reviewing 'sentinelgate render'.")
    FirewallEngine(Policy.from_yaml(policy_file)).apply_live(ruleset_path)
    click.echo(click.style("Ruleset validated and applied.", fg="green"))
