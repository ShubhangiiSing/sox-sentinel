import argparse
import json
from . import core

def main():
    parser=argparse.ArgumentParser(prog="sox-sentinel"); sub=parser.add_subparsers(dest="cmd",required=True)
    sub.add_parser("init"); sub.add_parser("seed-demo")
    run=sub.add_parser("run"); run.add_argument("--control",default="IAM-001")
    sub.add_parser("findings"); sub.add_parser("report"); sub.add_parser("verify-log")
    rep=sub.add_parser("reperform"); rep.add_argument("--run",required=True)
    server=sub.add_parser("serve"); server.add_argument("--host",default="127.0.0.1"); server.add_argument("--port",type=int,default=8000)
    args=parser.parse_args()
    if args.cmd=="init": core.init_db(); result={"initialized":True}
    elif args.cmd=="seed-demo": core.seed_demo(); result={"seeded":True}
    elif args.cmd=="run": result=core.execute(args.control)
    elif args.cmd=="findings": result=core.get_findings()
    elif args.cmd=="report": result=core.report()
    elif args.cmd=="verify-log": result=core.verify_audit_log()
    elif args.cmd=="reperform": result=core.reperform_run(args.run)
    else:
        from .api import serve
        serve(args.host,args.port); return
    print(json.dumps(result,indent=2,default=str))

if __name__=="__main__": main()
