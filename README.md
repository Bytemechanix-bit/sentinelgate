# SentinelGate 2.0

**Policy-as-code, zero-trust network enforcement with deterministic simulation, nftables rendering, validation, and PCI DSS evidence mapping.**

SentinelGate treats firewall policy as code: the same YAML policy is validated, simulated without root/network access, rendered to nftables, and mapped to compliance evidence.

## What changed in 2.0

- **Policy validation** catches invalid IPs/CIDRs, ports, rate limits, duplicate names, missing justifications, and invalid combinations before deployment.
- **Explicit priorities** make rule ordering deterministic and auditable.
- **Improved state simulation** tracks source/destination ports and recognizes reverse-direction established traffic.
- **Rate limiting stays outside the state cache**, preventing a rate-limited flow from bypassing the limiter.
- **IPv6-aware matching/rendering** is supported.
- **Machine-readable simulation** is available with `--json-output` for SIEM/automation integration.
- **Live apply is guarded** by an explicit `--yes`, root check, and `nft -c` configuration validation before load.
- Compliance output is positioned as **audit evidence/support**, not a compliance certification.

## Architecture

```text
                policy.yaml
                    |
          +---------v----------+
          | validation + model |
          +---------+----------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
 deterministic simulator    nftables renderer
        |                       |
        v                       v
  verdict / JSON logs       Linux enforcement
        |
        v
 PCI DSS evidence mapping
```

## Install

```bash
pip install -e ".[dev]"
```

## Commands

```bash
# Validate before doing anything else
sentinelgate validate policies/example.yaml

# Review generated nftables
sentinelgate render policies/example.yaml

# Simulate representative traffic
sentinelgate simulate policies/example.yaml

# Machine-readable output
sentinelgate simulate policies/example.yaml --json-output

# Generate compliance evidence mapping
sentinelgate report policies/example.yaml > compliance_report.md

# Live deployment — Linux + nftables + root; intentionally explicit
sudo sentinelgate apply policies/example.yaml --yes
```

## Security model

1. **Default deny is enforced in the data model.** A policy cannot opt into default allow.
2. **Rules have explicit priorities.** Lower numbers are evaluated first, preventing accidental dependence on YAML order.
3. **Every rule requires a human-readable justification.** This creates useful review/audit context.
4. **Established flows are simulated with a five-tuple** (source/destination IP, protocol, source/destination port), including reverse traffic.
5. **Rate-limited rules are evaluated per packet** and are never promoted into the established-flow cache.
6. **Live deployment validates the generated nftables configuration with `nft -c` before loading it.**

## Important scope boundary

The Python simulator is a **test model**, not a replacement for the Linux kernel's conntrack implementation. It is intentionally deterministic and lightweight. Production validation should include integration tests on the target Linux/nftables version.

Likewise, PCI DSS mappings are **control/evidence references**, not an attestation of compliance.

## Testing

```bash
pytest -q
```

The tests cover default-deny behavior, IPv4/IPv6 matching, port validation, priority ordering, reverse-flow state handling, rate limiting, and nftables rendering.

## Recommended next steps

- nftables integration tests in a disposable Linux network namespace
- rule shadow/conflict analysis
- signed/versioned policy bundles
- JSONL audit logs with timestamps and policy hashes
- Prometheus metrics
- SIEM export
- RBAC and approval workflow for live policy changes
- formal PCI DSS evidence objects with owner/status/review date

## License

MIT — see `LICENSE`.
