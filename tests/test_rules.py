import pytest

from sentinelgate.rules import Action, Packet, Policy, Protocol, Rule


def make_policy(rules):
    return Policy(name="test-policy", rules=rules, default_action=Action.DENY)


def test_default_action_must_be_deny():
    with pytest.raises(ValueError):
        Policy(name="bad", rules=[], default_action=Action.ALLOW)


def test_rule_matches_cidr_and_ipv6():
    rule = Rule("r1", Action.ALLOW, Protocol.TCP, src="10.0.0.0/24", dst_port="22", comment="admin")
    assert rule.matches(Packet("10.0.0.5", "1.2.3.4", "tcp", 22))
    assert not rule.matches(Packet("10.0.1.5", "1.2.3.4", "tcp", 22))
    v6 = Rule("v6", Action.ALLOW, Protocol.TCP, src="2001:db8::/32", dst_port="443", comment="v6")
    assert v6.matches(Packet("2001:db8::10", "2001:db8::20", "tcp", 443))


def test_rule_matches_ports():
    rule = Rule("r2", Action.DENY, Protocol.TCP, dst_port="21,23,8000-8010", comment="legacy")
    assert rule.matches(Packet("1.1.1.1", "2.2.2.2", "tcp", 23))
    assert rule.matches(Packet("1.1.1.1", "2.2.2.2", "tcp", 8005))
    assert not rule.matches(Packet("1.1.1.1", "2.2.2.2", "tcp", 25))


def test_policy_validation_catches_bad_port_and_missing_comment():
    with pytest.raises(ValueError, match="dst_port"):
        make_policy([Rule("bad", Action.ALLOW, Protocol.TCP, dst_port="70000", comment="")])


def test_priority_is_deterministic():
    p = make_policy([
        Rule("allow", Action.ALLOW, Protocol.TCP, dst_port="443", comment="web", priority=20),
        Rule("deny", Action.DENY, Protocol.TCP, dst_port="443", comment="blocked", priority=10),
    ])
    assert [r.name for r in p.ordered_rules()] == ["deny", "allow"]


def test_nftables_contains_stateful_default_deny():
    p = make_policy([Rule("allow-ssh", Action.ALLOW, Protocol.TCP, dst_port="22", comment="mgmt")])
    nft = p.to_nftables()
    assert "policy drop" in nft
    assert "ct state established,related accept" in nft
    assert "ct state invalid drop" in nft
    assert "SentinelGate-DROP" in nft
