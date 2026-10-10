#!/usr/bin/env python3
"""SENTINEL-X local REST API + static frontend server; Python stdlib only."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import sqlite3, json, sys, re, os, hashlib, urllib.request, urllib.error, socket
from datetime import datetime, timezone
from windows_collector import collect_event_metadata

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "sentinel_x.db"
WEB = ROOT / "web"
RULES = {
    ("Windows Defender Operational", 5007): {
        "rule_id": "SX-DEF-001", "title": "Defender configuration changed", "severity": "review",
        "reason": "Configuration changes can be legitimate; correlate with known updates or administrator actions.",
        "next_step": "Confirm the change was expected in Windows Security and correlate with known updates. Do not assume compromise."
    },
    ("PowerShell Operational", 4100): {
        "rule_id": "SX-PS-001", "title": "PowerShell warning event", "severity": "review",
        "reason": "Warning metadata warrants context; event ID alone does not establish malicious activity.",
        "next_step": "If unexpected, inspect locally in Event Viewer and correlate the timestamp with known activity."
    },
    ("PowerShell Operational", 4103): {
        "rule_id": "SX-PS-002", "title": "PowerShell module logging event", "severity": "info",
        "reason": "Module logging is telemetry, not a threat by itself.",
        "next_step": "Correlate with adjacent events only if activity is unexpected."
    },
    ("PowerShell Operational", 4104): {
        "rule_id": "SX-PS-003", "title": "PowerShell script-block logging event", "severity": "info",
        "reason": "Script-block logging records activity; contextual analysis is required.",
        "next_step": "Review details locally only when justified; do not upload sensitive script content."
    },
}
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
def connect():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, event_id INTEGER NOT NULL,
      level TEXT NOT NULL, timestamp TEXT NOT NULL, summary TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings(
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_db_id INTEGER NOT NULL, rule_id TEXT NOT NULL,
      title TEXT NOT NULL, severity TEXT NOT NULL, reason TEXT NOT NULL, next_step TEXT NOT NULL,
      created_at TEXT NOT NULL, FOREIGN KEY(event_db_id) REFERENCES events(id))""")
    # Prevent duplicate findings if triage is run repeatedly, including on existing databases.
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_event_rule ON findings(event_db_id, rule_id)")
    c.commit()
    return c
def event_dict(row):
    d=dict(row); d["synthetic"]=bool(d["synthetic"]); return d
def triage_event(c, event):
    rule=RULES.get((event["source"],int(event["event_id"])))
    if not rule: return None
    c.execute("""INSERT OR IGNORE INTO findings(event_db_id,rule_id,title,severity,reason,next_step,created_at)
      VALUES(?,?,?,?,?,?,?)""",(event["id"],rule["rule_id"],rule["title"],rule["severity"],rule["reason"],rule["next_step"],now()))
    return rule
def run_tests():
    cases=[
      (("Windows Defender Operational",5007),"SX-DEF-001"),
      (("PowerShell Operational",4100),"SX-PS-001"),
      (("PowerShell Operational",4103),"SX-PS-002"),
      (("PowerShell Operational",4104),"SX-PS-003"),
      (("PowerShell Operational",9999),None),
    ]
    results=[]
    for (source,eid),expected in cases:
        r=RULES.get((source,eid)); actual=r["rule_id"] if r else None
        results.append({"expected":expected,"actual":actual,"passed":expected==actual})
    return {"passed":sum(x["passed"] for x in results),"total":len(results),"results":results,
            "scope":"Rule wiring only; not real-world detection accuracy."}
def seed_demo(c):
    fixtures=[
      ("Windows Defender Operational",5007,"Information","Synthetic Defender configuration-change event"),
      ("PowerShell Operational",4100,"Warning","Synthetic PowerShell warning event"),
      ("PowerShell Operational",4103,"Information","Synthetic PowerShell module logging event"),
      ("PowerShell Operational",4104,"Information","Synthetic script-block logging event"),
      ("System",12,"Information","Synthetic power-management event"),
      ("PowerShell Operational",9999,"Information","Synthetic negative-test event"),
    ]
    stamp=now()
    for source,eid,level,summary in fixtures:
        c.execute("INSERT INTO events(source,event_id,level,timestamp,summary,synthetic) VALUES(?,?,?,?,?,1)",
                  (source,eid,level,stamp,summary))
    c.commit()
    rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(len(fixtures),)).fetchall()
    for row in rows: triage_event(c,dict(row))
    c.commit()
    return len(fixtures)
class Handler(BaseHTTPRequestHandler):
    server_version="SENTINEL-X/1.0"
    def log_message(self, fmt, *args):
        # Local demo server logs route/status only; no request bodies.
        sys.stderr.write("%s - %s\n"%(self.address_string(),fmt%args))
    def send_json(self, status, payload):
        raw=json.dumps(payload,indent=2).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Access-Control-Allow-Origin","http://127.0.0.1:8080")
        self.send_header("Access-Control-Allow-Headers","Content-Type"); self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.end_headers(); self.wfile.write(raw)
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin","http://127.0.0.1:8080")
        self.send_header("Access-Control-Allow-Headers","Content-Type"); self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.end_headers()
    def do_GET(self):
        parsed=urlparse(self.path); path=parsed.path; qs=parse_qs(parsed.query)
        if path.startswith("/api/"):
            with connect() as c:
                if path=="/api/health":
                    return self.send_json(200,{"status":"ok","service":"SENTINEL-X API","mode":"windows-read-only-polling" if sys.platform == "win32" else "synthetic-demo-only","database":"SQLite","real_endpoint_collection":sys.platform == "win32","collection_mode":"read-only Windows Event Log metadata, on-demand plus browser polling" if sys.platform == "win32" else "synthetic-demo-only","poll_interval_seconds":30 if sys.platform == "win32" else None})
                if path=="/api/summary":
                    events=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
                    findings=c.execute("SELECT COUNT(*) n FROM findings WHERE severity='review'").fetchone()["n"]
                    return self.send_json(200,{"events":events,"review_leads":findings,"sources":3,"tests":run_tests()})
                if path=="/api/events":
                    try: limit=max(1,min(200,int(qs.get("limit",["50"])[0])))
                    except (ValueError, TypeError): return self.send_json(400,{"error":"limit must be an integer from 1 to 200"})
                    rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
                    return self.send_json(200,{"items":[event_dict(r) for r in rows]})
                if path=="/api/findings":
                    try: limit=max(1,min(200,int(qs.get("limit",["50"])[0])))
                    except (ValueError, TypeError): return self.send_json(400,{"error":"limit must be an integer from 1 to 200"})
                    rows=c.execute("""SELECT f.*,e.source,e.event_id,e.timestamp AS event_timestamp
                      FROM findings f JOIN events e ON e.id=f.event_db_id ORDER BY f.id DESC LIMIT ?""",(limit,)).fetchall()
                    return self.send_json(200,{"items":[dict(r) for r in rows]})
            return self.send_json(404,{"error":"Not found"})
        public_routes={"/":"web/index.html","/index.html":"web/index.html","/privacy":"web/privacy.html","/privacy.html":"web/privacy.html","/terms":"web/terms.html","/terms.html":"web/terms.html","/favicon.svg":"web/favicon.svg"}
        relative=public_routes.get(path)
        if relative:
            target=(ROOT/relative).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file(): self.send_error(404); return
            data=target.read_bytes()
            ctype={".html":"text/html; charset=utf-8",".svg":"image/svg+xml; charset=utf-8"}.get(target.suffix,"application/octet-stream")
            self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(data)))
            self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","no-referrer")
            self.end_headers(); self.wfile.write(data); return
        self.send_error(404)
    def do_POST(self):
        path=urlparse(self.path).path
        length=int(self.headers.get("Content-Length","0"))
        if length>16000:
            return self.send_json(413,{"error":"Request too large (maximum 16 KB)"})
        body = {}
        if length:
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict): return self.send_json(400,{"error":"JSON body must be an object"})
            except (ValueError, UnicodeDecodeError): return self.send_json(400,{"error":"Invalid JSON"})
        if path=="/api/analyze/url":
            raw=str(body.get("url", "")).strip()[:2048]
            if not raw: return self.send_json(400,{"error":"Enter a URL to analyze."})
            from urllib.parse import urlsplit
            candidate=raw if "://" in raw else "https://"+raw
            try: u=urlsplit(candidate); host=(u.hostname or "").lower().rstrip(".")
            except ValueError: host=""
            if not host or any(ch.isspace() for ch in host): return self.send_json(400,{"error":"URL format is invalid."})
            reasons=[]; score=0
            if u.scheme not in ("http","https"): score+=35; reasons.append("Non-web URL scheme")
            if u.username or u.password: score+=35; reasons.append("URL contains embedded user information")
            if host.startswith("xn--") or ".xn--" in host: score+=25; reasons.append("Internationalized/punycode domain; verify the displayed domain carefully")
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",host): score+=25; reasons.append("URL uses an IP address instead of a domain")
            if host.count("-")>=3: score+=10; reasons.append("Domain contains many hyphens")
            if len(host)>60: score+=10; reasons.append("Unusually long hostname")
            if host.count(".")>=4: score+=10; reasons.append("Deeply nested subdomains")
            if any(x in (u.path+"?"+u.query).lower() for x in ("login","verify","password","credential","wallet","recover")):
                score+=10; reasons.append("Path/query contains a sensitive-account keyword; context matters")
            if len(u.query)>180: score+=5; reasons.append("Long query string")
            try:
                ip=socket.getaddrinfo(host,None, type=socket.SOCK_STREAM)
                dns="resolves" if ip else "no address returned"
            except (OSError, socket.gaierror): dns="not resolved (offline, typo, or DNS failure)"
            score=min(100,score)
            verdict="High risk indicators" if score>=50 else "Review carefully" if score>=20 else "No obvious heuristic indicators"
            if not reasons: reasons=["No listed heuristic matched. This is not proof the URL is safe."]
            return self.send_json(200,{"ok":True,"type":"url-analysis","input":raw,"host":host,"score":score,"verdict":verdict,"reasons":reasons,"dns_status":dns,"checked_at":now(),"limitations":"Heuristic-only analysis; no reputation feed or page content checked. Never enter credentials based on this result."})
        if path=="/api/analyze/email":
            raw=str(body.get("text", "")).strip()[:12000]
            if not raw: return self.send_json(400,{"error":"Paste email text or headers to analyze."})
            low=raw.lower(); reasons=[]; score=0
            patterns=[(r"\b(urgent|immediately|within 24 hours|account suspended|action required)\b",15,"Urgency or pressure language"),(r"\b(password|verify your account|sign in|login|credentials)\b",15,"Credential/account language"),(r"\b(gift card|wire transfer|crypto|payment overdue|invoice attached)\b",15,"Payment or transfer request language"),(r"\b(attachment|enable macros|download the file)\b",10,"Attachment or download language"),(r"\b(otp|one.time password|security code)\b",20,"One-time code requested or mentioned"),(r"https?://[^\s<>]+",10,"Contains one or more links")]
            for pat,pts,label in patterns:
                if re.search(pat,low): score+=pts; reasons.append(label)
            fromaddr=re.search(r"(?im)^from:\s*(.+)$",raw)
            replyto=re.search(r"(?im)^reply-to:\s*(.+)$",raw)
            if fromaddr and replyto and fromaddr.group(1).strip().lower()!=replyto.group(1).strip().lower(): score+=20; reasons.append("From and Reply-To headers differ; investigate legitimacy")
            score=min(100,score); verdict="High suspicion" if score>=50 else "Needs review" if score>=20 else "No strong text indicators"
            if not reasons: reasons=["No listed text indicators matched. Sender authenticity and attachments remain unverified."]
            return self.send_json(200,{"ok":True,"type":"email-analysis","score":score,"verdict":verdict,"reasons":reasons,"checked_at":now(),"limitations":"Text heuristics only; sender authentication, links, attachments, and delivery path were not independently verified."})
        if path=="/api/scan/folder":
            folder=str(body.get("path", "")).strip()
            if not folder: return self.send_json(400,{"error":"Choose a folder path on this PC."})
            target=Path(folder).expanduser().resolve()
            if not target.is_dir(): return self.send_json(400,{"error":"Folder does not exist or is not a directory."})
            # Bounded local-only scan: text-like files, size/count limits, no uploads, no modification.
            exts={".txt",".md",".csv",".json",".py",".js",".html",".xml",".ini",".log",".yaml",".yml",".env",".ps1",".config"}
            rules=[("Possible private key",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),35),("Cloud/API token pattern",re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{20,})\b"),30),("Password/secret assignment",re.compile(r"(?i)\b(password|passwd|client_secret|api_key|access_token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']"),20),("Possible Aadhaar-like number",re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),10),("Email address",re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),3)]
            scanned=0; skipped=0; findings=[]; maxfiles=1500
            try:
                for f in target.rglob("*"):
                    if scanned+skipped>=maxfiles: break
                    if not f.is_file(): continue
                    if f.suffix.lower() not in exts: skipped+=1; continue
                    try:
                        if f.stat().st_size>1_000_000: skipped+=1; continue
                        text=f.read_text(encoding="utf-8",errors="ignore")
                    except OSError: skipped+=1; continue
                    scanned+=1
                    for label,rx,weight in rules:
                        matches=list(rx.finditer(text))
                        if matches:
                            findings.append({"file":str(f.relative_to(target)),"type":label,"matches":min(len(matches),100),"risk":"High" if weight>=30 else "Review" if weight>=10 else "Low","note":"Value is not displayed or stored; inspect locally."})
                            if len(findings)>=250: break
                    if len(findings)>=250: break
            except OSError as exc: return self.send_json(400,{"error":"Folder scan could not complete: "+str(exc)[:180]})
            return self.send_json(200,{"ok":True,"folder":str(target),"scanned_files":scanned,"skipped_files":skipped,"findings":findings,"checked_at":now(),"limitations":"Local, read-only scan of selected text-like files only. Pattern matches can be false positives; binary files, cloud activity and outbound transfers are not monitored."})
        if path=="/api/check/password":
            password=str(body.get("password", ""))
            if not password or len(password)>1024: return self.send_json(400,{"error":"Enter a password (maximum 1024 characters)."})
            # HIBP Pwned Passwords k-anonymity: only the first 5 SHA-1 hex chars are sent.
            digest=hashlib.sha1(password.encode("utf-8")).hexdigest().upper(); prefix,suffix=digest[:5],digest[5:]
            try:
                req=urllib.request.Request("https://api.pwnedpasswords.com/range/"+prefix,headers={"Add-Padding":"true","User-Agent":"SENTINEL-X-local-check/1.0"})
                with urllib.request.urlopen(req,timeout=8) as response: data=response.read(2000000).decode("ascii","ignore")
                count=0
                for line in data.splitlines():
                    parts=line.split(":")
                    if len(parts)==2 and parts[0].strip().upper()==suffix: count=int(parts[1].strip()); break
                return self.send_json(200,{"ok":True,"checked":True,"found":count>0,"exposure_count":count,"method":"Pwned Passwords range k-anonymity","checked_at":now(),"privacy":"Password itself and full hash were not sent; only first 5 SHA-1 hex characters were requested. SHA-1 is used only for lookup, not password storage."})
            except Exception:
                return self.send_json(503,{"ok":False,"checked":False,"error":"Could not reach the breach-check service. No conclusion can be made; check internet and retry."})
        if path=="/api/tests/run":
            return self.send_json(200,run_tests())
        if path=="/api/collect/windows":
            result = collect_event_metadata()
            if not result.get("ok"):
                return self.send_json(501 if not result.get("available") else 503, result)
            inserted = 0
            with connect() as c:
                for item in result.get("events", []):
                    exists = c.execute("SELECT id FROM events WHERE source=? AND event_id=? AND timestamp=? AND synthetic=0 LIMIT 1",
                                        (item["source"], item["event_id"], item["timestamp"])).fetchone()
                    if exists:
                        continue
                    c.execute("INSERT INTO events(source,event_id,level,timestamp,summary,synthetic) VALUES(?,?,?,?,?,0)",
                              (item["source"], item["event_id"], item["level"], item["timestamp"], item["summary"]))
                    event = dict(c.execute("SELECT * FROM events WHERE id=last_insert_rowid()").fetchone())
                    triage_event(c, event)
                    inserted += 1
                c.commit()
            return self.send_json(200, {"ok":True,"available":True,"found":len(result.get("events", [])),"inserted":inserted,
                                        "logs":result.get("logs", []),"partial":result.get("partial", False),
                                        "collected_at":result.get("collected_at"),
                                        "message":"Read-only event metadata collected. Event messages and script contents were not stored."})
        if path in ("/api/demo/seed","/api/triage"):
            with connect() as c:
                if path=="/api/demo/seed":
                    n=seed_demo(c)
                    return self.send_json(200,{"ok":True,"inserted":n,"message":"Synthetic demo events inserted; no endpoint logs were read."})
                rows=c.execute("SELECT * FROM events").fetchall()
                before=c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
                for row in rows: triage_event(c,dict(row))
                c.commit()
                after=c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
                return self.send_json(200,{"ok":True,"events_reviewed":len(rows),"new_findings":after-before})
        return self.send_json(404,{"error":"Unknown endpoint"})
if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("--host",default="127.0.0.1"); parser.add_argument("--port",type=int,default=8080)
    args=parser.parse_args()
    if args.port < 1 or args.port > 65535: parser.error("--port must be between 1 and 65535")
    with connect() as c:
        count=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        # Do not mix fabricated events into a Windows live collection database.
        if count==0 and sys.platform != "win32": seed_demo(c)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error("For safety, this prototype binds to loopback only; do not expose it to a network.")
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f"SENTINEL-X API running at http://{args.host}:{args.port}")
    print("Mode: read-only Windows Event Log polling" if sys.platform == "win32" else "Mode: synthetic demo only (live collection requires Windows).")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping SENTINEL-X.")
    finally: server.server_close()
