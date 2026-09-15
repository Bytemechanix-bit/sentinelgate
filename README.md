# SentinelGate

SentinelGate is a policy-driven Linux firewall engine built around **policy-as-code**. Security rules live in YAML, are validated and tested before deployment, and can be rendered into nftables rules for Linux.

## Five layers

1. **Policy** — define allow, deny, and rate-limit rules in YAML.
2. **Validation & conflict detection** — catch malformed rules and ambiguous overlapping rules with different actions at the same priority before deployment.
3. **Simulation** — exercise packets against the policy without touching the host firewall.
4. **Enforcement & real Linux testing** — render nftables and validate the generated ruleset against a real Linux nftables installation in CI.
5. **Audit & controlled change** — write timestamped JSONL audit events and require an approval record bound to the exact policy hash before live deployment.

## Why this is useful

The main goal is not to replace nftables. Linux/nftables remains the enforcement layer. SentinelGate provides a repeatable way to define, review, test, and audit the policy that gets enforced.

## Quick start

```bash
pip install -e ".[dev]"
sentinelgate validate policies/example.yaml --fail-on-conflict
sentinelgate conflicts policies/example.yaml
sentinelgate render policies/example.yaml
sentinelgate simulate policies/example.yaml --json-output --audit-log /tmp/sentinelgate-audit.jsonl
sentinelgate report policies/example.yaml
```

## Rule conflict detection

SentinelGate flags ambiguous overlaps where rules have different actions and the same priority. Different priorities are treated as an explicit precedence decision, so intentional block-before-allow or allow-before-block policies are not incorrectly reported as conflicts.

```bash
sentinelgate conflicts policies/example.yaml
```

## Audit trail

Simulation can write timestamped JSON Lines events:

```bash
sentinelgate simulate policies/example.yaml --audit-log /tmp/sentinelgate-audit.jsonl
```

The log captures the decision, matched rule, traffic details, reason, and UTC timestamp. Deployment also records the approved policy hash and approver.

## Controlled deployment

Live deployment is deliberately guarded. A policy must be reviewed and approved separately, the approval is tied to the SHA-256 hash of the policy file, and the requester cannot be the approver when both identities are supplied.

```bash
sentinelgate approve policies/example.yaml --approver "reviewer-name"
SENTINELGATE_REQUESTER="change-author" sentinelgate apply policies/example.yaml \
  --approval .sentinelgate/approvals/example.json --yes
```

`apply` also validates the generated ruleset with `nft -c` before loading it. **Do not run live apply on a production or primary workstation without reviewing the generated ruleset first.** The default renderer uses `flush ruleset`.

For a real team, the approval command should be paired with GitHub branch protection/rulesets that require pull-request review and prevent direct pushes to `main`. The local approval record demonstrates the change-control logic inside the project; GitHub is the appropriate place to enforce the human approval gate.

## Real Linux integration tests

The integration suite uses an actual Linux `nft` binary and runs in a dedicated Ubuntu GitHub Actions job. It validates the generated ruleset with `nft -c`, so the project is tested against the real Linux firewall tool rather than only the Python simulator. A production-grade test environment can extend this to an isolated network namespace and actual packet flows.

## CI / DevSecOps

GitHub Actions runs:

- Ruff linting
- Bandit security scanning
- Pytest unit tests
- Policy validation and conflict checks
- nftables rendering/simulation checks
- A real Linux/nftables integration validation

This makes security and quality checks part of the development workflow instead of a manual final step.

## Scope

SentinelGate currently targets **Linux host inbound filtering**. The generated ruleset uses an `input` chain. It is not yet a complete router/gateway implementation with forwarding, NAT, or outbound policy enforcement.

## License

MIT
