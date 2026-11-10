"""Auditable, deterministic SOX control testing over SQLite."""
import csv
import hashlib
import io
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("SOX_SENTINEL_DB", "sox_sentinel.db"))
EVIDENCE_DIR = Path(os.environ.get("SOX_SENTINEL_EVIDENCE", "evidence"))

CONTROLS = [
    ("IAM-001", "Logical Access", "Terminated employee active account", "Detect active accounts belonging to terminated employees."),
    ("IAM-002", "Logical Access", "Privileged access approval", "Detect privileged accounts without current approval."),
    ("IAM-003", "Logical Access", "Unowned application account", "Detect application accounts without an identifiable owner."),
    ("IAM-004", "Logical Access", "Inactive privileged account", "Detect privileged accounts inactive for more than 90 days."),
    ("CHG-001", "Change Management", "Change approval before deployment", "Detect deployments before approval or without approval."),
    ("CHG-002", "Change Management", "Change testing evidence", "Detect production changes without recorded testing evidence."),
    ("CHG-003", "Change Management", "Change segregation of duties", "Detect self-approved production changes."),
    ("OPS-001", "IT Operations", "Backup job completion", "Detect failed scheduled backup jobs."),
    ("OPS-002", "IT Operations", "Incident SLA compliance", "Detect incidents exceeding their response SLA."),
    ("OPS-003", "IT Operations", "Disaster recovery evidence", "Detect DR tests without completion evidence."),
]

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def connect(path=None):
    db = sqlite3.connect(str(path or DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db(path=None):
    db = connect(path)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS controls (id TEXT PRIMARY KEY, domain TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS employees (employee_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS accounts (account_id TEXT PRIMARY KEY, employee_id TEXT, system TEXT NOT NULL, active INTEGER NOT NULL, privileged INTEGER NOT NULL, approved INTEGER NOT NULL, last_login TEXT, FOREIGN KEY(employee_id) REFERENCES employees(employee_id));
    CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, collected_at TEXT NOT NULL, path TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, control_id TEXT NOT NULL, status TEXT NOT NULL, executed_at TEXT NOT NULL, summary TEXT NOT NULL, evidence_ids TEXT NOT NULL, FOREIGN KEY(control_id) REFERENCES controls(id));
    CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, control_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', owner TEXT, FOREIGN KEY(run_id) REFERENCES runs(id));
    CREATE TABLE IF NOT EXISTS remediation (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, action TEXT NOT NULL, owner TEXT NOT NULL, due_date TEXT, status TEXT NOT NULL DEFAULT 'OPEN', updated_at TEXT NOT NULL, FOREIGN KEY(finding_id) REFERENCES findings(id));
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, detail TEXT NOT NULL);
    """)
    for row in CONTROLS:
        db.execute("INSERT OR IGNORE INTO controls VALUES (?,?,?,?)", row)
    _migrate(db)
    db.commit(); db.close()


GENESIS_HASH = "0" * 64


def _columns(db, table):
    return {row["name"] for row in db.execute("PRAGMA table_info(%s)" % table)}


def _add_column(db, table, column, ddl):
    if column not in _columns(db, table):
        db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, ddl))


def _canonical_hash(value):
    """SHA-256 of a stable JSON encoding, so the same data always hashes the same."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash, at, action, entity_type, entity_id, detail):
    return _canonical_hash([prev_hash, at, action, entity_type, entity_id, detail])


def _migrate(db):
    """Bring older databases up to the current schema without losing history."""
    # 1. Population snapshot: every run keeps the exact records it tested.
    db.execute("""CREATE TABLE IF NOT EXISTS run_population (
        run_id TEXT NOT NULL, seq INTEGER NOT NULL, record TEXT NOT NULL,
        PRIMARY KEY (run_id, seq), FOREIGN KEY(run_id) REFERENCES runs(id))""")
    _add_column(db, "runs", "population_count", "INTEGER")
    _add_column(db, "runs", "population_sha256", "TEXT")

    # 2. Hash-chained audit log: each entry commits to the one before it.
    _add_column(db, "audit_log", "prev_hash", "TEXT")
    _add_column(db, "audit_log", "entry_hash", "TEXT")
    unchained = db.execute("SELECT 1 FROM audit_log WHERE entry_hash IS NULL LIMIT 1").fetchone()
    if unchained:
        prev = GENESIS_HASH
        for row in db.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            entry = row["entry_hash"] or _entry_hash(prev, row["at"], row["action"], row["entity_type"], row["entity_id"], row["detail"])
            if row["entry_hash"] is None:
                db.execute("UPDATE audit_log SET prev_hash=?, entry_hash=? WHERE id=?", (prev, entry, row["id"]))
            prev = entry

    # Block edits and deletes on records that must never change.
    for table in ("audit_log", "runs", "run_population"):
        for op in ("UPDATE", "DELETE"):
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS %s_no_%s BEFORE %s ON %s "
                "BEGIN SELECT RAISE(ABORT, '%s is append-only'); END" % (table, op.lower(), op, table, table)
            )

    # 3. Finding de-duplication: one finding per underlying issue, linked to every run that saw it.
    _add_column(db, "findings", "finding_key", "TEXT")
    _add_column(db, "findings", "last_seen_run_id", "TEXT")
    _add_column(db, "findings", "occurrences", "INTEGER NOT NULL DEFAULT 1")
    db.execute("""CREATE TABLE IF NOT EXISTS run_findings (
        run_id TEXT NOT NULL, finding_id TEXT NOT NULL, is_new INTEGER NOT NULL,
        PRIMARY KEY (run_id, finding_id),
        FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(finding_id) REFERENCES findings(id))""")
    db.execute("INSERT OR IGNORE INTO run_findings SELECT run_id, id, 1 FROM findings")
    db.execute("CREATE INDEX IF NOT EXISTS findings_by_key ON findings(finding_key, status)")


def log(db, action, kind, entity, detail=""):
    last = db.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["entry_hash"] if last and last["entry_hash"] else GENESIS_HASH
    at = utcnow()
    entry = _entry_hash(prev, at, action, kind, entity, detail)
    db.execute(
        "INSERT INTO audit_log(at,action,entity_type,entity_id,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?)",
        (at, action, kind, entity, detail, prev, entry),
    )


def verify_audit_log(path=None):
    """Walk the hash chain. Any edited, deleted or reordered entry breaks it."""
    init_db(path); db = connect(path)
    rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall(); db.close()
    prev = GENESIS_HASH
    for row in rows:
        expected = _entry_hash(prev, row["at"], row["action"], row["entity_type"], row["entity_id"], row["detail"])
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return {"valid": False, "entries": len(rows), "first_broken_id": row["id"]}
        prev = row["entry_hash"]
    return {"valid": True, "entries": len(rows), "first_broken_id": None, "head_hash": prev}

def seed_demo(path=None):
    init_db(path); db=connect(path)
    db.execute("INSERT OR REPLACE INTO employees VALUES ('E-100','Morgan Lee','TERMINATED')")
    db.execute("INSERT OR REPLACE INTO employees VALUES ('E-200','Avery Patel','ACTIVE')")
    db.execute("INSERT OR REPLACE INTO accounts VALUES ('aws-mlee','E-100','AWS Production',1,1,0,'2026-11-08')")
    db.execute("INSERT OR REPLACE INTO accounts VALUES ('aws-apatel','E-200','AWS Production',1,1,1,'2026-11-08')")
    log(db,"DEMO_SEEDED","dataset","employees/accounts","Synthetic records loaded")
    db.commit(); db.close()

def upload_evidence(filename, data, path=None):
    init_db(path); root=EVIDENCE_DIR if path is None else Path(str(path)+".evidence")
    root.mkdir(parents=True,exist_ok=True); digest=hashlib.sha256(data).hexdigest(); eid=str(uuid.uuid4())
    safe=Path(filename).name
    if not safe or len(data)>20*1024*1024: raise ValueError("Invalid filename or evidence exceeds 20 MiB")
    target=root/(eid+"_"+safe); target.write_bytes(data)
    db=connect(path); db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?)",(eid,safe,digest,len(data),utcnow(),str(target))); log(db,"EVIDENCE_UPLOADED","evidence",eid,digest); db.commit(); db.close()
    return {"id":eid,"filename":safe,"sha256":digest,"size":len(data)}

def verify_evidence(evidence_id, path=None):
    db=connect(path); row=db.execute("SELECT * FROM evidence WHERE id=?",(evidence_id,)).fetchone(); db.close()
    if not row: raise KeyError(evidence_id)
    p=Path(row["path"]); actual=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
    return {"id":evidence_id,"valid":actual==row["sha256"],"expected_sha256":row["sha256"],"actual_sha256":actual}

def import_access_csv(data, path=None):
    init_db(path); reader=csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    required={"employee_id","employee_name","employment_status","account_id","system","active","privileged","approved","last_login"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise ValueError("CSV requires columns: "+", ".join(sorted(required)))
    db=connect(path); count=0
    for row in reader:
        status=row["employment_status"].strip().upper()
        active=int(row["active"].strip().lower() in ("1","true","yes","active"))
        privileged=int(row["privileged"].strip().lower() in ("1","true","yes")); approved=int(row["approved"].strip().lower() in ("1","true","yes"))
        db.execute("INSERT OR REPLACE INTO employees VALUES (?,?,?)",(row["employee_id"],row["employee_name"],status))
        db.execute("INSERT OR REPLACE INTO accounts VALUES (?,?,?,?,?,?,?)",(row["account_id"],row["employee_id"] or None,row["system"],active,privileged,approved,row["last_login"] or None)); count+=1
    log(db,"ACCESS_DATA_IMPORTED","dataset","accounts",str(count)); db.commit(); db.close(); return count

def execute(control_id="IAM-001", evidence_ids=None, path=None):
    init_db(path); db=connect(path)
    control=db.execute("SELECT * FROM controls WHERE id=?",(control_id,)).fetchone()
    if not control: db.close(); raise KeyError(control_id)
    evidence_ids=evidence_ids or []
    for eid in evidence_ids:
        if not db.execute("SELECT 1 FROM evidence WHERE id=?",(eid,)).fetchone(): db.close(); raise ValueError("Unknown evidence id: "+eid)
    population = _population(db, control_id)
    implemented = control_id in IMPLEMENTED
    exceptions = _evaluate(control_id, population)
    summary = {"records_tested": len(population), "exceptions": len(exceptions), "message": "Control evaluated"}
    if not implemented:
        summary["message"] = "Procedure is catalogued; dataset-specific execution is not yet implemented"
    if exceptions:
        status = "EXCEPTION"
    elif not implemented or not population:
        status = "INCONCLUSIVE"
    else:
        status = "PASS"
    population_hash = _canonical_hash(population)
    summary["population_sha256"] = population_hash

    rid = str(uuid.uuid4()); now = utcnow()
    db.execute(
        "INSERT INTO runs(id,control_id,status,executed_at,summary,evidence_ids,population_count,population_sha256) VALUES (?,?,?,?,?,?,?,?)",
        (rid, control_id, status, now, json.dumps(summary), json.dumps(evidence_ids), len(population), population_hash),
    )
    for seq, record in enumerate(population):
        db.execute("INSERT INTO run_population VALUES (?,?,?)", (rid, seq, json.dumps(record, sort_keys=True)))
    log(db, "POPULATION_SNAPSHOT", "run", rid, "%d records sha256=%s" % (len(population), population_hash))

    new_count = 0
    for exc in exceptions:
        existing = db.execute(
            "SELECT id FROM findings WHERE finding_key=? AND status!='CLOSED' ORDER BY rowid LIMIT 1", (exc["key"],)
        ).fetchone()
        if existing:
            fid = existing["id"]
            db.execute("UPDATE findings SET last_seen_run_id=?, occurrences=occurrences+1 WHERE id=?", (rid, fid))
            db.execute("INSERT INTO run_findings VALUES (?,?,0)", (rid, fid))
            log(db, "FINDING_RECURRED", "finding", fid, exc["key"])
        else:
            fid = str(uuid.uuid4()); new_count += 1
            db.execute(
                "INSERT INTO findings(id,run_id,control_id,severity,title,detail,status,finding_key,last_seen_run_id,occurrences) "
                "VALUES(?,?,?,?,?,?,'OPEN',?,?,1)",
                (fid, rid, control_id, exc["severity"], exc["title"], exc["detail"], exc["key"], rid),
            )
            db.execute("INSERT INTO run_findings VALUES (?,?,1)", (rid, fid))
            log(db, "FINDING_CREATED", "finding", fid, exc["title"])
    log(db, "CONTROL_EXECUTED", "run", rid, status); db.commit()

    run_findings = db.execute(
        "SELECT f.id, f.severity, f.title, f.detail, f.occurrences, rf.is_new FROM run_findings rf "
        "JOIN findings f ON f.id=rf.finding_id WHERE rf.run_id=? ORDER BY f.rowid", (rid,)
    ).fetchall()
    result = {
        "id": rid, "control_id": control_id, "status": status, "executed_at": now, "summary": summary,
        "evidence_ids": evidence_ids, "new_findings": new_count,
        "findings": [dict(id=r["id"], severity=r["severity"], title=r["title"], detail=r["detail"],
                          occurrences=r["occurrences"], new=bool(r["is_new"])) for r in run_findings],
    }
    db.close(); return result


IMPLEMENTED = {"IAM-001", "IAM-002"}

_POPULATION_SQL = """SELECT a.account_id, a.employee_id, e.name AS employee_name, e.status AS employment_status,
    a.system, a.active, a.privileged, a.approved, a.last_login
    FROM accounts a LEFT JOIN employees e ON e.employee_id=a.employee_id WHERE %s ORDER BY a.account_id"""


def _population(db, control_id):
    """The exact records a control tests. Saved with the run so it can be re-performed later."""
    if control_id == "IAM-001":
        where = "a.active=1"
    elif control_id == "IAM-002":
        where = "a.active=1 AND a.privileged=1"
    else:
        return []
    return [dict(row) for row in db.execute(_POPULATION_SQL % where)]


def _evaluate(control_id, population):
    """Pure test logic: same population in, same exceptions out. No database access."""
    exceptions = []
    for r in population:
        if control_id == "IAM-001":
            if r["employment_status"] == "TERMINATED":
                exceptions.append({"key": "IAM-001:TERMINATED_ACTIVE:" + r["account_id"], "severity": "HIGH",
                                   "title": "Terminated employee has active account",
                                   "detail": "%s for %s remains active in %s." % (r["account_id"], r["employee_name"], r["system"])})
            elif r["employment_status"] is None:
                exceptions.append({"key": "IAM-001:NO_OWNER:" + r["account_id"], "severity": "MEDIUM",
                                   "title": "Account has no employee owner",
                                   "detail": "%s has no matching employee record." % r["account_id"]})
        elif control_id == "IAM-002" and not r["approved"]:
            exceptions.append({"key": "IAM-002:PRIV_UNAPPROVED:" + r["account_id"], "severity": "HIGH",
                               "title": "Privileged account lacks approval",
                               "detail": "%s has no recorded approval." % r["account_id"]})
    return exceptions


def reperform_run(run_id, path=None):
    """Re-run a past test against its saved population and confirm the same result."""
    init_db(path); db = connect(path)
    run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not run: db.close(); raise KeyError(run_id)
    if run["population_sha256"] is None:
        db.close()
        return {"run_id": run_id, "reperformable": False, "reason": "Run predates population snapshots"}
    population = [json.loads(r["record"]) for r in db.execute("SELECT record FROM run_population WHERE run_id=? ORDER BY seq", (run_id,))]
    recorded_keys = sorted(r["finding_key"] for r in db.execute(
        "SELECT f.finding_key FROM run_findings rf JOIN findings f ON f.id=rf.finding_id WHERE rf.run_id=?", (run_id,)))
    log(db, "RUN_REPERFORMED", "run", run_id, ""); db.commit(); db.close()
    actual_hash = _canonical_hash(population)
    reperformed_keys = sorted(e["key"] for e in _evaluate(run["control_id"], population))
    population_intact = actual_hash == run["population_sha256"] and len(population) == run["population_count"]
    result_matches = reperformed_keys == recorded_keys
    return {
        "run_id": run_id, "control_id": run["control_id"], "reperformable": True,
        "population_intact": population_intact, "result_matches": result_matches,
        "agrees": population_intact and result_matches,
        "expected_sha256": run["population_sha256"], "actual_sha256": actual_hash,
        "records": len(population), "recorded_exceptions": len(recorded_keys), "reperformed_exceptions": len(reperformed_keys),
    }


def get_run(run_id, path=None):
    init_db(path); db = connect(path)
    run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not run: db.close(); raise KeyError(run_id)
    population = [json.loads(r["record"]) for r in db.execute("SELECT record FROM run_population WHERE run_id=? ORDER BY seq", (run_id,))]
    db.close()
    return dict(run, summary=json.loads(run["summary"]), evidence_ids=json.loads(run["evidence_ids"]), population=population)

def create_remediation(finding_id, action, owner, due_date=None, path=None):
    db=connect(path); fid=str(uuid.uuid4())
    if not db.execute("SELECT 1 FROM findings WHERE id=?",(finding_id,)).fetchone(): db.close(); raise KeyError(finding_id)
    db.execute("INSERT INTO remediation VALUES(?,?,?,?,?,'OPEN',?)",(fid,finding_id,action,owner,due_date,utcnow())); log(db,"REMEDIATION_CREATED","remediation",fid,owner); db.commit(); db.close()
    return {"id":fid,"finding_id":finding_id,"action":action,"owner":owner,"due_date":due_date,"status":"OPEN"}

def update_remediation(remediation_id, status, path=None):
    if status not in ("OPEN","IN_PROGRESS","COMPLETED","CANCELLED"): raise ValueError("Invalid remediation status")
    db=connect(path); cur=db.execute("UPDATE remediation SET status=?,updated_at=? WHERE id=?",(status,utcnow(),remediation_id))
    if not cur.rowcount: db.close(); raise KeyError(remediation_id)
    log(db,"REMEDIATION_UPDATED","remediation",remediation_id,status); db.commit(); row=db.execute("SELECT * FROM remediation WHERE id=?",(remediation_id,)).fetchone(); result=dict(row); db.close(); return result

def get_findings(path=None):
    init_db(path); db = connect(path)
    rows = db.execute(
        "SELECT f.*, r.executed_at, COALESCE(l.executed_at, r.executed_at) AS last_seen_at FROM findings f "
        "JOIN runs r ON r.id=f.run_id LEFT JOIN runs l ON l.id=f.last_seen_run_id "
        "ORDER BY last_seen_at DESC"
    ).fetchall()
    out = [dict(r) for r in rows]; db.close(); return out

def report(path=None):
    init_db(path); db = connect(path)
    runs = [dict(r) for r in db.execute("SELECT * FROM runs ORDER BY executed_at DESC")]; db.close()
    return {"generated_at": utcnow(), "runs": runs, "findings": get_findings(path), "audit_log": verify_audit_log(path)}

