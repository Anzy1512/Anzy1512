# Analyst case study — synthetic authentication activity

**Scope:** 13 entirely synthetic authentication events in `data/auth_events.jsonl`, dated 2026-10-01. This is a controlled teaching dataset, not telemetry from a real company.

## Question

Can a small set of time-based authentication rules highlight activity worth investigating without labeling every failed login malicious?

## Observations

| Finding | Evidence | Initial assessment |
| --- | --- | --- |
| Repeated login failures | Five failures against `alice` from `203.0.113.10` between 09:00 and 09:03 UTC | Matches configured password-guessing threshold; intent unknown |
| Success after failures | A success for `alice` from the same source at 09:03:40 UTC after five failures | Higher-priority review; success alone does not prove compromise |
| Possible password spray | Five failures from `198.51.100.20` against four accounts between 09:20 and 09:22 UTC | Matches configured cross-account threshold; could also reflect shared infrastructure |
| Benign comparison | One failure and a later success for `frank` from `192.0.2.50` | Below all configured thresholds; no alert |

IP addresses come from documentation-only TEST-NET ranges; they do **not** identify real attackers.

## Investigation workflow

1. Validate event timestamps, authentication source and log completeness.
2. Look for MFA outcomes, account lockouts, device identity and related successful sessions.
3. For the cross-account pattern, determine whether the source represents a shared gateway or automation.
4. Preserve raw event references, then classify each finding as true positive, benign positive, false positive or insufficient evidence.
5. Escalate only under a documented incident-response process; do not automatically disable accounts from these findings.

## Assessment

The three detection rules behaved as expected on the fixture. Eleven local unit tests passed at development time. No claim is made about real-world detection accuracy, incident attribution or production readiness.

**What I'd improve next:** ingest normalized Windows 4624/4625 and SSH logs, build per-user/environment baselines, add alert correlation and compare outputs to a manually labeled evaluation dataset. Only then could measured precision and recall be reported.

See the [triage runbook](triage-runbook.md) and the [lab README](../README.md).
