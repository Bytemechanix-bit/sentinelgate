from sentinelgate.engine import FirewallEngine
from sentinelgate.rules import Action, Packet, Policy, Protocol, Rule


def policy(rules):
    return Policy("test", rules, Action.DENY)


def test_default_deny():
    v = FirewallEngine(policy([])).evaluate(Packet("1.2.3.4", "5.6.7.8", "tcp", 9999))
    assert v.action == Action.DENY and v.matched_rule == "DEFAULT_DENY"


def test_priority_controls_conflict():
    p = policy([
        Rule("allow-web", Action.ALLOW, Protocol.TCP, dst_port="443", comment="web", priority=20),
        Rule("block-web", Action.DENY, Protocol.TCP, dst_port="443", comment="block", priority=10),
    ])
    v = FirewallEngine(p).evaluate(Packet("1.2.3.4", "10.0.0.1", "tcp", 443, 50000))
    assert v.action == Action.DENY and v.matched_rule == "block-web"


def test_established_reverse_flow_fast_path():
    e = FirewallEngine(policy([Rule("ssh", Action.ALLOW, Protocol.TCP, dst_port="22", comment="ssh")]))
    first = e.evaluate(Packet("10.0.0.5", "10.0.0.1", "tcp", 22, 50000))
    reverse = e.evaluate(Packet("10.0.0.1", "10.0.0.5", "tcp", 50000, 22))
    assert first.action == Action.ALLOW
    assert reverse.matched_rule == "ESTABLISHED"


def test_rate_limit_does_not_enter_established_cache():
    e = FirewallEngine(policy([Rule("rl", Action.RATE_LIMIT, Protocol.TCP, dst_port="443", rate_limit="3/second", comment="limit")]))
    results = [e.evaluate(Packet("9.9.9.9", "10.0.0.1", "tcp", 443, 40000)).action for _ in range(5)]
    assert results.count(Action.ALLOW) == 3
    assert results.count(Action.DENY) == 2
