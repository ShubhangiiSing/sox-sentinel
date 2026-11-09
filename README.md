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
| GET | `/report` | Retrieve JSON workpaper data |

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

## Architecture and data model

`sox_sentinel/core.py` contains SQLite schema creation, ingestion, evidence integrity checks, controls, findings, remediation, and JSON report assembly. `api.py` exposes those operations through a small standard-library WSGI JSON API, and `cli.py` supports local operation. Tables: `controls`, `employees`, `accounts`, `evidence`, `runs`, `findings`, `remediation`, and append-only `audit_log`.

## Known gaps and next steps


This is the first working vertical slice, not the full master specification. The requested FastAPI/Pydantic/SQLAlchemy/Alembic stack, PostgreSQL, complete change and operations test engines, auth/RBAC and organisation isolation, AWS connectors, anomaly detection, Docker, CI, Terraform, and production deployment are not implemented. The current environment has Python 3.9.6 and no FastAPI/SQLAlchemy installation, so this slice uses only the standard library to stay runnable here. Evidence upload has a 20 MiB limit and stores files locally. There is no malware scanning or authentication. No AWS resources are provisioned.
