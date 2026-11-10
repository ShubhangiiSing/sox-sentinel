"""Tests for the three audit-trust properties: re-performance, tamper evidence, finding de-duplication."""
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sox_sentinel import core

CSV_HEADER = b"employee_id,employee_name,employment_status,account_id,system,active,privileged,approved,last_login\n"


class PopulationSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_run_can_be_reperformed_after_source_data_changes(self):
        core.seed_demo(self.db)
        run = core.execute("IAM-001", path=self.db)
        self.assertEqual(run["status"], "EXCEPTION")

        # HR later corrects the record and a new population is imported, overwriting the live tables.
        core.import_access_csv(CSV_HEADER + b"E-100,Morgan Lee,TERMINATED,aws-mlee,AWS Production,0,1,0,2026-11-08\n", self.db)
        self.assertEqual(core.execute("IAM-001", path=self.db)["findings"], [])

        # The original run still holds the exact records it tested and re-performs to the same result.
        saved = core.get_run(run["id"], self.db)
        self.assertEqual(len(saved["population"]), 2)
        self.assertIn("aws-mlee", [r["account_id"] for r in saved["population"]])
        check = core.reperform_run(run["id"], self.db)
        self.assertTrue(check["agrees"])
        self.assertEqual(check["reperformed_exceptions"], 1)

    def test_population_snapshot_cannot_be_edited(self):
        core.seed_demo(self.db)
        run = core.execute("IAM-001", path=self.db)
        db = core.connect(self.db)
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("UPDATE run_population SET record='{}' WHERE run_id=?", (run["id"],))
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("DELETE FROM runs WHERE id=?", (run["id"],))
        db.close()

    def test_tampered_snapshot_is_detected(self):
        core.seed_demo(self.db)
        run = core.execute("IAM-001", path=self.db)
        db = core.connect(self.db)
        db.execute("DROP TRIGGER run_population_no_update")  # simulate someone bypassing the guard
        db.execute("UPDATE run_population SET record=replace(record,'TERMINATED','ACTIVE') WHERE run_id=?", (run["id"],))
        db.commit(); db.close()
        check = core.reperform_run(run["id"], self.db)
        self.assertFalse(check["population_intact"])
        self.assertFalse(check["agrees"])


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.db"
        core.seed_demo(self.db)
        core.execute("IAM-001", path=self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_chain_is_valid_after_normal_use(self):
        result = core.verify_audit_log(self.db)
        self.assertTrue(result["valid"])
        self.assertGreater(result["entries"], 3)

    def test_update_and_delete_are_blocked(self):
        db = core.connect(self.db)
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("UPDATE audit_log SET detail='edited'")
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("DELETE FROM audit_log")
        db.close()

    def _bypass_guards(self):
        db = core.connect(self.db)
        db.execute("DROP TRIGGER audit_log_no_update")
        db.execute("DROP TRIGGER audit_log_no_delete")
        return db

    def test_edited_entry_breaks_chain(self):
        db = self._bypass_guards()
        db.execute("UPDATE audit_log SET detail='nothing to see' WHERE id=2"); db.commit(); db.close()
        result = core.verify_audit_log(self.db)
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_broken_id"], 2)

    def test_deleted_entry_breaks_chain(self):
        db = self._bypass_guards()
        db.execute("DELETE FROM audit_log WHERE id=2"); db.commit(); db.close()
        self.assertFalse(core.verify_audit_log(self.db)["valid"])

    def test_report_includes_log_verification(self):
        self.assertTrue(core.report(self.db)["audit_log"]["valid"])


class FindingDeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.db"
        core.seed_demo(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_rerun_links_existing_finding(self):
        first = core.execute("IAM-001", path=self.db)
        second = core.execute("IAM-001", path=self.db)
        self.assertEqual(first["new_findings"], 1)
        self.assertEqual(second["new_findings"], 0)
        self.assertEqual(second["status"], "EXCEPTION")  # still an exception in this run
        self.assertEqual(second["findings"][0]["id"], first["findings"][0]["id"])
        findings = core.get_findings(self.db)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["occurrences"], 2)
        self.assertEqual(findings[0]["last_seen_run_id"], second["id"])

    def test_different_issues_stay_separate(self):
        core.import_access_csv(CSV_HEADER + b",,,svc-orphan,Payroll,1,0,0,\n", self.db)
        run = core.execute("IAM-001", path=self.db)
        self.assertEqual(run["new_findings"], 2)
        self.assertEqual(len(core.execute("IAM-001", path=self.db)["findings"]), 2)
        self.assertEqual(len(core.get_findings(self.db)), 2)

    def test_closed_finding_recurring_opens_new_one(self):
        first = core.execute("IAM-001", path=self.db)
        db = core.connect(self.db)
        db.execute("UPDATE findings SET status='CLOSED' WHERE id=?", (first["findings"][0]["id"],)); db.commit(); db.close()
        again = core.execute("IAM-001", path=self.db)
        self.assertEqual(again["new_findings"], 1)
        self.assertNotEqual(again["findings"][0]["id"], first["findings"][0]["id"])


class MigrationTests(unittest.TestCase):
    """A database created by v0.1.0 (before these fixes) must upgrade in place."""

    def test_legacy_database_upgrades(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db_path = Path(temp.name) / "legacy.db"
        db = sqlite3.connect(str(db_path))
        db.executescript("""
        CREATE TABLE controls (id TEXT PRIMARY KEY, domain TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL);
        CREATE TABLE employees (employee_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE accounts (account_id TEXT PRIMARY KEY, employee_id TEXT, system TEXT NOT NULL, active INTEGER NOT NULL, privileged INTEGER NOT NULL, approved INTEGER NOT NULL, last_login TEXT);
        CREATE TABLE evidence (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, collected_at TEXT NOT NULL, path TEXT NOT NULL);
        CREATE TABLE runs (id TEXT PRIMARY KEY, control_id TEXT NOT NULL, status TEXT NOT NULL, executed_at TEXT NOT NULL, summary TEXT NOT NULL, evidence_ids TEXT NOT NULL);
        CREATE TABLE findings (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, control_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', owner TEXT);
        CREATE TABLE remediation (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, action TEXT NOT NULL, owner TEXT NOT NULL, due_date TEXT, status TEXT NOT NULL DEFAULT 'OPEN', updated_at TEXT NOT NULL);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, detail TEXT NOT NULL);
        INSERT INTO runs VALUES ('old-run','IAM-001','EXCEPTION','2026-11-09T00:00:00+00:00','{}','[]');
        INSERT INTO findings(id,run_id,control_id,severity,title,detail) VALUES ('old-f','old-run','IAM-001','HIGH','t','d');
        INSERT INTO audit_log(at,action,entity_type,entity_id,detail) VALUES ('2026-11-09T00:00:00+00:00','CONTROL_EXECUTED','run','old-run','EXCEPTION');
        """)
        db.commit(); db.close()

        core.seed_demo(db_path)
        self.assertTrue(core.verify_audit_log(db_path)["valid"])
        self.assertFalse(core.reperform_run("old-run", db_path)["reperformable"])
        self.assertEqual(len(core.get_findings(db_path)), 1)
        self.assertTrue(core.reperform_run(core.execute("IAM-001", path=db_path)["id"], db_path)["agrees"])


if __name__ == "__main__":
    unittest.main()
