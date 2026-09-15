from sentinelgate.engine import FirewallEngine
from sentinelgate.rules import Action, Packet, Policy, Protocol, Rule


def make_policy():
    return Policy("test", [
        Rule("ssh", Action.ALLOW, Protocol.TCP, src="10.0.0.0/24", dst_port="22", comment="admin", priority=10),
        Rule("web", Action.ALLOW, Protocol.TCP, dst_port="443", comment="web", priority=20),
    ])


def test_allowed_flow_and_reverse_are_established():
    engine = FirewallEngine(make_policy())
    first = engine.evaluate(Packet("10.0.0.5", "192.0.2.10", "tcp", 22, 50000))
    reverse = engine.evaluate(Packet("192.0.2.10", "10.0.0.5", "tcp", 50000, 22))
    assert first.action == Action.ALLOW
    assert reverse.matched_rule == "ESTABLISHED"


def test_unmatched_traffic_is_denied():
    verdict = FirewallEngine(make_policy()).evaluate(Packet("198.51.100.5", "192.0.2.10", "tcp", 25))
    assert verdict.action == Action.DENY
