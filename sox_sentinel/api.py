"""Small JSON API using Python's standard WSGI server; intended for local demos."""
import base64
import json
from pathlib import Path
from wsgiref.simple_server import make_server
from . import core

def application(environ, start_response):
    method=environ.get("REQUEST_METHOD","GET"); path=environ.get("PATH_INFO","")
    try:
        if method=="GET" and path in ("/","/app.js","/styles.css"):
            name={"/":"index.html","/app.js":"app.js","/styles.css":"styles.css"}[path]
            target=Path(__file__).with_name("frontend")/name
            payload=target.read_bytes(); mime="text/html; charset=utf-8" if name.endswith("html") else ("text/javascript; charset=utf-8" if name.endswith("js") else "text/css; charset=utf-8")
            start_response("200 OK",[("Content-Type",mime),("Content-Length",str(len(payload)))]); return [payload]
        length=int(environ.get("CONTENT_LENGTH") or 0)
        raw=environ["wsgi.input"].read(length) if length else b""
        body=json.loads(raw.decode("utf-8")) if raw else {}
        if method=="GET" and path=="/health": result={"status":"ok","service":"sox-sentinel"}; code="200 OK"
        elif method=="GET" and path=="/controls": result=[{"id":c[0],"domain":c[1],"name":c[2],"description":c[3]} for c in core.CONTROLS]; code="200 OK"
        elif method=="GET" and path=="/findings": result=core.get_findings(); code="200 OK"
        elif method=="GET" and path=="/report": result=core.report(); code="200 OK"
        elif method=="POST" and path=="/demo/seed": core.seed_demo(); result={"seeded":True}; code="201 Created"
        elif method=="POST" and path=="/imports/access": result={"rows_imported":core.import_access_csv(raw)}; code="201 Created"
        elif method=="POST" and path=="/evidence":
            result=core.upload_evidence(body["filename"],base64.b64decode(body["content_base64"],validate=True)); code="201 Created"
        elif method=="POST" and path=="/runs": result=core.execute(body.get("control_id","IAM-001"),body.get("evidence_ids",[])); code="201 Created"
        elif method=="POST" and path=="/remediations": result=core.create_remediation(body["finding_id"],body["action"],body["owner"],body.get("due_date")); code="201 Created"
        elif method=="PATCH" and path.startswith("/remediations/"):
            result=core.update_remediation(path.rsplit("/",1)[-1],body["status"]); code="200 OK"
        elif method=="GET" and path=="/audit-log/verify": result=core.verify_audit_log(); code="200 OK"
        elif method=="GET" and path.startswith("/runs/") and path.endswith("/reperform"):
            result=core.reperform_run(path.split("/")[2]); code="200 OK"
        elif method=="GET" and path.startswith("/runs/") and path.count("/")==2:
            result=core.get_run(path.split("/")[2]); code="200 OK"
        elif method=="GET" and path.startswith("/evidence/") and path.endswith("/verify"):
            result=core.verify_evidence(path.split("/")[2]); code="200 OK"
        else: result={"error":"not_found"}; code="404 Not Found"
    except (KeyError,ValueError,TypeError,json.JSONDecodeError) as exc:
        result={"error":"invalid_request","detail":str(exc)}; code="400 Bad Request"
    except Exception as exc:
        result={"error":"internal_error","detail":str(exc)}; code="500 Internal Server Error"
    payload=json.dumps(result,default=str).encode(); start_response(code,[("Content-Type","application/json"),("Content-Length",str(len(payload)))]); return [payload]

def serve(host="127.0.0.1", port=8000):
    core.init_db()
    print("SOX Sentinel API at http://%s:%s"%(host,port))
    make_server(host,port,application).serve_forever()
