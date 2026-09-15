import pytest

from sentinelgate.change_control import detect_conflicts, verify_approval, write_approval
from sentinelgate.rules import Action, Policy, Protocol, Rule


def test_conflict_detection_only_flags_ambiguous_same_priority_rules():
    policy = Policy("conflict", [
        Rule("allow-ssh", Action.ALLOW, Protocol.TCP, dst_port="22", comment="allow", priority=10),
        Rule("block-ssh", Action.DENY, Protocol.TCP, dst_port="22", comment="block", priority=10),
    ])
    assert len(detect_conflicts(policy)) == 1


def test_different_priority_rules_are_intentional_precedence():
    policy = Policy("precedence", [
        Rule("block-ssh", Action.DENY, Protocol.TCP, dst_port="22", comment="block", priority=10),
        Rule("allow-ssh", Action.ALLOW, Protocol.TCP, dst_port="22", comment="allow", priority=20),
    ])
    assert detect_conflicts(policy) == []


def test_approval_is_bound_to_policy_hash_and_separation_of_duties(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("name: test\ndefault_action: deny\nrules: []\n", encoding="utf-8")
    approval = write_approval(policy, "reviewer", tmp_path / "approvals")
    assert verify_approval(policy, approval, "requester")["approver"] == "reviewer"
    with pytest.raises(PermissionError, match="separation of duties"):
        verify_approval(policy, approval, "REVIEWER")
    policy.write_text("name: changed\ndefault_action: deny\nrules: []\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="does not match"):
        verify_approval(policy, approval, "requester")
