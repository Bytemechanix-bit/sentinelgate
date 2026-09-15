"""Integration check against a real Linux nftables binary."""
import os
import shutil
import subprocess  # nosec B404 - integration test intentionally invokes nft

import pytest

from sentinelgate.rules import Action, Policy, Protocol, Rule


@pytest.mark.integration
def test_generated_ruleset_passes_real_nftables_validation(tmp_path):
    if os.name != "posix" or shutil.which("nft") is None:
        pytest.skip("requires Linux and nftables")
    policy = Policy("integration", [Rule("https", Action.ALLOW, Protocol.TCP, dst_port="443", comment="test")])
    ruleset = tmp_path / "integration.nft"
    ruleset.write_text(policy.to_nftables(), encoding="utf-8")
    result = subprocess.run(["nft", "-c", "-f", str(ruleset)], capture_output=True, text=True, check=False)  # nosec B603
    if os.geteuid() != 0 and result.returncode != 0:
        pytest.skip("nftables validation requires sufficient netfilter privileges")
    assert result.returncode == 0, result.stderr
