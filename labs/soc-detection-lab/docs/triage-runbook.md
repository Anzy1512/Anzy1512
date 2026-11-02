# Authentication Alert Triage Runbook

This is a practice playbook for synthetic events; no alert here establishes malicious intent.

## 1. Validate the detection

- Confirm event schema, time zones, host identity and ingestion completeness.
- Examine the underlying failures and successes in chronological order.
- Check whether alerts are artifacts of test accounts, retrying applications or shared NAT gateways.

## 2. Enrich when authorized

- Verify account ownership, account lockout/MFA policy and expected access times.
- Cross-check IdP, VPN, host and change-management records.
- Review IP provenance, authentication method, device and sign-in risk only with approved data sources.

## 3. Decide and document

- Mark **True Positive**, **Benign Positive**, **False Positive** or **Insufficient Evidence**.
- Separate observations from hypotheses; preserve event timestamps and links to permitted evidence.
- Escalate suspicious successful authentications to an authorized incident responder.

## 4. Contain under policy

- Do not automatically block IPs or disable accounts from this lab's output.
- If confirmed and approved, follow organizational incident processes for session revocation, password reset and MFA checks.

## 5. Tune and measure

- Measure precision/false-positive rate against reviewed samples, not unverified labels.
- Consider per-environment baselines, lockout patterns, service accounts, NAT aggregation, and peak login times.
- Add regression fixtures when tuning thresholds.

**Current known limitation:** each rule emits the first qualifying alert for a grouping key in a batch, so repeat attacks later in the same input file can be under-reported. This lab does not include continuous ingestion, distributed correlation, or deduplication across runs.
