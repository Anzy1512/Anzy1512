# SOC Detection Lab — Authentication Activity

A small, offline detection-engineering exercise built with Python's standard library. It ingests synthetic JSONL authentication events, detects three review-worthy patterns, and produces structured JSON findings.

**Status:** Demonstration / educational lab. Not a SIEM, production detector, or verified real-world incident response system. No live data, credentials, network calls, cloud resources, Docker, or paid services required.

## Quick start

From this directory, using Python 3.11+:

```powershell
python main.py --input data/auth_events.jsonl
python -m unittest discover -s tests -v
python main.py --output findings.json
```

The sample contains **13 synthetic events** and should produce **three alerts**:

| Rule | Trigger | ATT&CK mapping |
| --- | --- | --- |
| `repeated_login_failures` | Five failures for one account/source in 5 minutes | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| `possible_password_spray` | Five failures affecting at least three accounts from one source in 10 minutes | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| `success_after_failures` | A success following at least three failures for the same account/source in 10 minutes | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

ATT&CK mappings describe possible behavior, **not proof of attribution or compromise**. Thresholds are deliberately chosen for the fixture and require tuning before operational use.

## Input contract

One JSON object per line with six required string fields:

```json
{"timestamp":"2026-10-01T09:00:00Z","host":"vpn-gw-01","user":"alice","src_ip":"203.0.113.10","event_type":"authentication","outcome":"failure"}
```

`timestamp` must be ISO 8601 with timezone. `event_type` must be `authentication`; `outcome` is `success` or `failure`; `src_ip` must be a valid IPv4 or IPv6 address. Invalid records stop processing and report their line number. All example addresses are documentation-only TEST-NET ranges.

## Method and limitations

1. Validate and normalize events to UTC, then sort chronologically.
2. Find per-source/per-account failure bursts and multi-account bursts.
3. Check successful authentications for recent preceding failures.
4. Emit one first-match finding per detection/grouping key per invocation (not a continuous alert stream).

**Limitations:** The lab does not correlate distinct source IPs, distinguish shared NAT traffic, recognize successful MFA, identify bots or attackers, or establish compromise. Windows Event ID 4625, Linux SSH logs and IdP events must be normalized into the specified JSONL schema externally. Small samples can cause false positives; a large batch may consume significant memory. There is no enrichment, alert persistence, production access control, or data-retention policy.

**Review the results:** [Sample JSON findings](sample_output.json) · [Analyst case study](docs/analyst-case-study.md)

## Investigation exercise

Read [the triage runbook](docs/triage-runbook.md). Investigate the source address, user, host and timing; compare related authentication events; check MFA and device context where available; record what is observed versus hypothesized before recommending account protection or IP-blocking decisions.

## Repository contents

- `detector.py` — input validation, grouping and detection logic.
- `main.py` — CLI producing JSON findings.
- `data/auth_events.jsonl` — reproducible, synthetic input.
- `tests/test_detector.py` — offline regression and negative tests.
- `docs/triage-runbook.md` — analyst workflow and limitations.

## Responsible use

Only analyze logs you are authorized to handle. Do not commit genuine credentials, private logs, personal data or production tokens. Sample data is deliberately fictional.