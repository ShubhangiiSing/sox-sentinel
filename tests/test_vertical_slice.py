import hashlib
import tempfile
import unittest
from pathlib import Path
from io import BytesIO
from sox_sentinel import core
from sox_sentinel.api import application

class VerticalSliceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=Path(self.temp.name)/"test.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_terminated_employee_workflow(self):
        uploaded=core.upload_evidence("iam.csv",b"synthetic IAM export",self.db)
        core.seed_demo(self.db)
        run=core.execute("IAM-001",[uploaded["id"]],self.db)
        self.assertEqual(run["status"],"EXCEPTION")
        self.assertEqual(run["summary"]["records_tested"],2)
        self.assertEqual(run["findings"][0]["title"],"Terminated employee has active account")
        self.assertTrue(core.verify_evidence(uploaded["id"],self.db)["valid"])
        action=core.create_remediation(run["findings"][0]["id"],"Disable account and retain ticket","IT Operations",path=self.db)
        self.assertEqual(core.update_remediation(action["id"],"COMPLETED",self.db)["status"],"COMPLETED")

    def test_changed_evidence_is_detected(self):
        item=core.upload_evidence("source.txt",b"original",self.db)
        db=core.connect(self.db)
        file_path=db.execute("SELECT path FROM evidence WHERE id=?",(item["id"],)).fetchone()["path"]
        db.close()
        Path(file_path).write_bytes(b"changed")
        self.assertFalse(core.verify_evidence(item["id"],self.db)["valid"])

    def test_no_records_is_not_pass(self):
        core.init_db(self.db)
        self.assertEqual(core.execute("IAM-001",path=self.db)["status"],"INCONCLUSIVE")

    def test_sha256_metadata(self):
        item=core.upload_evidence("file.csv",b"data",self.db)
        self.assertEqual(item["sha256"],hashlib.sha256(b"data").hexdigest())

    def test_dashboard_static_routes(self):
        for route,marker in (("/","SOX Sentinel"),("/app.js","function refresh"),("/styles.css","--navy")):
            captured={}
            def start(status,headers): captured.update(status=status,headers=headers)
            response=b"".join(application({"REQUEST_METHOD":"GET","PATH_INFO":route,"CONTENT_LENGTH":"0","wsgi.input":BytesIO()},start))
            self.assertEqual(captured["status"],"200 OK")
            self.assertIn(marker.encode(),response)

if __name__=="__main__":
    unittest.main()
