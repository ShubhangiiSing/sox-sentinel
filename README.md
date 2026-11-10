# SOX Sentinel

SOX Sentinel is a local-first prototype for repeatable IT SOX control checks. It produces preliminary results for auditor review; it does not decide control effectiveness. Missing populations produce `INCONCLUSIVE`, never `PASS`.

## Current repository assessment

The starting repository contained no source code, configuration, tests, or Git metadata. This first vertical slice adds a SQLite persistence layer, a synthetic terminated-employee scenario, access control procedures, evidence hashing, a JSON API, remediation tracking, and report retrieval.

## Run the local demonstration

Requires Python 3.9+ and no third-party packages:

```sh
python3 -m sox_sentinel.cli init
python3 -m sox_sentinel.cli seed-demo
python3 -m sox_sentinel.cli run --control IAM-001
python3 -m sox_sentinel.cli findings
python3 -m sox_sentinel.cli report
python3 -m sox_sentinel.cli verify-log
python3 -m sox_sentinel.cli reperform --run <run-id>
```

The demo creates a fictional terminated employee, Morgan Lee, with an active privileged AWS account. The run should return `EXCEPTION` and create a finding. Database and evidence locations can be set with `SOX_SENTINEL_DB` and `SOX_SENTINEL_EVIDENCE`.

Run the app with `python3 -m sox_sentinel.cli serve`; it binds to `127.0.0.1:8000` by default. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) for the browser dashboard. Use **Load demo data**, then **Run IAM-001** to see the terminated-user exception. You can also upload evidence, verify its hash, create remediation actions, and download the JSON workpaper from the dashboard. Example API calls:

```sh
curl -X POST http://127.0.0.1:8000/demo/seed
curl -X POST http://127.0.0.1:8000/runs -H 'Content-Type: application/json' -d '{"control_id":"IAM-001"}'
curl http://127.0.0.1:8000/findings
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health status |
| GET | `/controls` | Control catalogue |
| POST | `/demo/seed` | Load synthetic access records |
| POST | `/imports/access` | Import CSV access population |
| POST | `/evidence` | Upload base64 evidence with filename and content |
| GET | `/evidence/{id}/verify` | Recalculate evidence SHA-256 |
| POST | `/runs` | Execute a control with optional evidence IDs |
| GET | `/findings` | Retrieve findings |
| POST | `/remediations` | Create a remediation action |
| PATCH | `/remediations/{id}` | Update remediation status |
| GET | `/report` | Retrieve JSON workpaper data, including audit log verification |
| GET | `/runs/{id}` | Run details with the exact population it tested |
| GET | `/runs/{id}/reperform` | Re-run a past test on its saved population and compare results |
| GET | `/audit-log/verify` | Check the audit log hash chain |

Access CSV columns: `employee_id,employee_name,employment_status,account_id,system,active,privileged,approved,last_login`. CSV import preserves the supplied original as separately uploaded evidence; importing alone does not archive a source file.

## Implemented controls

| ID | Domain | Current execution |
|---|---|---|
| IAM-001 | Logical access | Finds active accounts for terminated or unmatched employees |
| IAM-002 | Logical access | Finds active privileged accounts without approval |
| IAM-003, IAM-004 | Logical access | Catalogued; execution is inconclusive |
| CHG-001 to CHG-003 | Change management | Catalogued; execution is inconclusive |
| OPS-001 to OPS-003 | IT operations | Catalogued; execution is inconclusive |

All control runs, findings, evidence references, and remediation changes are persisted in SQLite. The local API is unauthenticated and intended only for a trusted development machine; it is not safe to expose to a network. The implementation is deterministic and uses no AI to make audit decisions.

## Audit trust

Three properties support reliance on the tool's output:

- **Re-performance.** Every run saves the exact records it tested (`run_population`) and their SHA-256 hash. Re-importing data later does not change past runs. `reperform --run <id>` (or `GET /runs/{id}/reperform`) re-runs the test on the saved population and confirms the population is intact and produces the same exceptions.
- **Tamper-evident audit log.** Database triggers block `UPDATE` and `DELETE` on `audit_log`, `runs` and `run_population`. Each log entry also stores the hash of the previous entry, so an edited, deleted or re-ordered entry breaks the chain. `verify-log` reports the first broken entry, and the workpaper includes the result. This detects tampering but does not prevent it. Someone with file access could rewrite the whole chain or drop the newest entries. To catch that, record the `head_hash` from each workpaper outside the tool.
- **One finding per issue.** Each exception has a stable key (control, exception type, account). Re-running a control links a recurring exception to the existing open finding and increments `occurrences` and `last_seen_run_id`, instead of opening a duplicate. Every run still records which findings it observed (`run_findings`). A finding marked `CLOSED` that recurs opens a new finding.

Databases from v0.1.0 upgrade automatically on next use. Existing log entries are chained, and older runs report that they predate population snapshots. Findings created before the upgrade have no key, so the first run after upgrading opens one new finding per existing issue.

## Architecture and data model

`sox_sentinel/core.py` contains SQLite schema creation, ingestion, evidence integrity checks, controls, findings, remediation, and JSON report assembly. `api.py` exposes those operations through a small standard-library WSGI JSON API, and `cli.py` supports local operation. Tables: `controls`, `employees`, `accounts`, `evidence`, `runs`, `run_population`, `findings`, `run_findings`, `remediation`, and a hash-chained, append-only `audit_log`.

## Known gaps and next steps


This is the first working vertical slice, not the full master specification. The requested FastAPI/Pydantic/SQLAlchemy/Alembic stack, PostgreSQL, complete change and operations test engines, auth/RBAC and organisation isolation, AWS connectors, anomaly detection, Docker, CI, Terraform, and production deployment are not implemented. The current environment has Python 3.9.6 and no FastAPI/SQLAlchemy installation, so this slice uses only the standard library to stay runnable here. Evidence upload has a 20 MiB limit and stores files locally. There is no malware scanning or authentication. No AWS resources are provisioned.
