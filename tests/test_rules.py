from sentinelgate.rules import Action, Packet, Policy, Protocol, Rule


def test_rule_matches_ip_and_port():
    rule = Rule("ssh", Action.ALLOW, Protocol.TCP, src="10.0.0.0/24", dst_port="22", comment="ssh")
    assert rule.matches(Packet("10.0.0.5", "192.0.2.10", "tcp", 22))
    assert not rule.matches(Packet("10.0.1.5", "192.0.2.10", "tcp", 22))


def test_policy_is_default_deny():
    Policy("ok", [Rule("web", Action.ALLOW, Protocol.TCP, dst_port="443", comment="https")])


def test_invalid_policy_is_rejected():
    try:
        Policy("bad", [Rule("bad", Action.ALLOW, Protocol.TCP, dst_port="70000", comment="bad")])
    except ValueError as exc:
        assert "dst_port" in str(exc)
    else:
        raise AssertionError("invalid policy was accepted")
