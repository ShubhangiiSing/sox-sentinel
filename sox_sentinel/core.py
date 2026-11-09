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
    db.commit(); db.close()

def log(db, action, kind, entity, detail=""):
    db.execute("INSERT INTO audit_log(at,action,entity_type,entity_id,detail) VALUES(?,?,?,?,?)", (utcnow(), action, kind, entity, detail))

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
    findings=[]; status="PASS"; summary={"records_tested":0,"exceptions":0,"message":"Control evaluated"}
    if control_id=="IAM-001":
        rows=db.execute("SELECT a.*,e.name,e.status FROM accounts a LEFT JOIN employees e ON e.employee_id=a.employee_id WHERE a.active=1").fetchall()
        summary["records_tested"]=len(rows)
        for r in rows:
            if r["status"]=="TERMINATED": findings.append(("HIGH","Terminated employee has active account",r["account_id"]+" for "+str(r["name"])+" remains active in "+r["system"]+"."))
            elif r["status"] is None: findings.append(("MEDIUM","Account has no employee owner",r["account_id"]+" has no matching employee record."))
    elif control_id=="IAM-002":
        rows=db.execute("SELECT a.*,e.name FROM accounts a LEFT JOIN employees e USING(employee_id) WHERE active=1 AND privileged=1 AND approved=0").fetchall(); summary["records_tested"]=db.execute("SELECT count(*) FROM accounts WHERE active=1 AND privileged=1").fetchone()[0]
        findings=[("HIGH","Privileged account lacks approval",r["account_id"]+" has no recorded approval.") for r in rows]
    else:
        summary.update(records_tested=0,message="Procedure is catalogued; dataset-specific execution is not yet implemented")
        status="INCONCLUSIVE"
    summary["exceptions"]=len(findings)
    if findings: status="EXCEPTION"
    elif summary["records_tested"]==0: status="INCONCLUSIVE"
    rid=str(uuid.uuid4()); now=utcnow()
    db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",(rid,control_id,status,now,json.dumps(summary),json.dumps(evidence_ids)))
    for severity,title,detail in findings:
        fid=str(uuid.uuid4()); db.execute("INSERT INTO findings(id,run_id,control_id,severity,title,detail,status) VALUES(?,?,?,?,?,?,?)",(fid,rid,control_id,severity,title,detail,"OPEN")); log(db,"FINDING_CREATED","finding",fid,title)
    log(db,"CONTROL_EXECUTED","run",rid,status); db.commit()
    result={"id":rid,"control_id":control_id,"status":status,"executed_at":now,"summary":summary,"evidence_ids":evidence_ids,"findings":[dict(id=r[0],severity=r[1],title=r[2],detail=r[3]) for r in db.execute("SELECT id,severity,title,detail FROM findings WHERE run_id=?",(rid,))]}
    db.close(); return result

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
    db=connect(path); rows=db.execute("SELECT f.*,r.executed_at FROM findings f JOIN runs r ON r.id=f.run_id ORDER BY r.executed_at DESC").fetchall(); out=[dict(r) for r in rows]; db.close(); return out

def report(path=None):
    db=connect(path); runs=[dict(r) for r in db.execute("SELECT * FROM runs ORDER BY executed_at DESC")]; findings=get_findings(path); db.close(); return {"generated_at":utcnow(),"runs":runs,"findings":findings}

