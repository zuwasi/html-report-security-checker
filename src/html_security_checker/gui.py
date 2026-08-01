"""Browser-based GUI for HTML Report Security Checker."""

import http.server
import json
from pathlib import Path
import socketserver
import threading
import webbrowser
from urllib.parse import urlparse

from ._version import __version__
from .checker import Checker
from .email_alert import EmailAlert, EmailConfig, load_config, save_config

HTML_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HTML Report Security Checker</title>
<style>
:root{color-scheme:dark;--bg:#0a0e1a;--panel:#111827;--line:#243044;--cyan:#00d9ff;--green:#10b981;--red:#ef4444;--orange:#f59e0b;--blue:#3b82f6;--muted:#94a3b8}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#102848 0,transparent 35%),var(--bg);color:#e5edf7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh}
.wrap{width:min(1200px,94%);margin:auto;padding:36px 0}header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}h1{font-size:clamp(1.5rem,4vw,2.5rem);margin:0;background:linear-gradient(90deg,#fff,var(--cyan));background-clip:text;color:transparent}.version{color:var(--cyan);border:1px solid #155e75;border-radius:99px;padding:5px 11px}
.card{background:linear-gradient(145deg,rgba(17,24,39,.96),rgba(13,20,34,.96));border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 18px 50px #0005;margin-bottom:18px}.row{display:flex;gap:12px;align-items:center}.path{flex:1}input,button{font:inherit}input{width:100%;color:#f8fafc;background:#080d18;border:1px solid #334155;border-radius:10px;padding:12px;outline:none}input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #00d9ff18}button{border:0;border-radius:10px;padding:12px 18px;font-weight:700;cursor:pointer;background:linear-gradient(120deg,var(--cyan),#0891b2);color:#03131b}button:hover{filter:brightness(1.12)}button.secondary{background:#253248;color:#e2e8f0}button:disabled{opacity:.45;cursor:not-allowed}
.drop{margin-top:16px;padding:30px;border:2px dashed #334155;border-radius:14px;text-align:center;color:var(--muted);transition:.2s}.drop.over{border-color:var(--cyan);background:#00d9ff0a}.hint,.status{color:var(--muted);font-size:.9rem}.status{min-height:1.2em;margin:12px 0 0}.badges{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.badge{border-radius:99px;padding:7px 12px;font-weight:700}.error{background:#ef444422;color:#fca5a5}.warning{background:#f59e0b22;color:#fcd34d}.info{background:#3b82f622;color:#93c5fd}
.table-wrap{overflow:auto;border-radius:12px;border:1px solid var(--line)}table{border-collapse:collapse;width:100%;min-width:850px}th,td{text-align:left;padding:11px;border-bottom:1px solid #263144;vertical-align:top}th{background:#162033;color:var(--cyan);position:sticky;top:0}tr.error td{background:#ef44440c}tr.warning td{background:#f59e0b0c}tr.info td{background:#3b82f60c}.sev{text-transform:uppercase;font-weight:800}.empty{text-align:center;color:var(--green);padding:32px}.hidden{display:none!important}
details summary{cursor:pointer;font-weight:700;color:var(--cyan)}.toggle{display:flex;gap:8px;align-items:center;margin:16px 0}.toggle input{width:auto}.grid{display:grid;grid-template-columns:2fr 1fr 2fr;gap:12px}.grid .wide{grid-column:span 2}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}footer{text-align:center;color:#64748b;margin-top:28px;font-size:.85rem}
@media(max-width:700px){.row{align-items:stretch;flex-direction:column}.grid{grid-template-columns:1fr}.grid .wide{grid-column:auto}.wrap{padding-top:22px}.card{padding:15px}}
</style></head><body><main class="wrap">
<header><h1>HTML Report Security Checker</h1><span class="version" id="version">v...</span></header>
<section class="card" id="scanner"><div class="row"><input class="path" id="path" placeholder="C:\path\to\report.html or folder"><button class="secondary" id="browse">Browse</button><button id="scan">Scan</button></div><input type="file" id="fileInput" accept=".html,.htm" style="display:none"><div class="drop" id="drop"><strong>Drop HTML files here</strong><br><span class="hint">Click Browse to pick a file, drag &amp; drop, or enter a full path above.</span></div><div class="status" id="status"></div></section>
<section class="card hidden" id="results"><div class="row"><h2 style="flex:1;margin:0">Scan Results</h2><button class="secondary" id="again">Scan Another</button></div><div class="badges"><span class="badge error" id="errors"></span><span class="badge warning" id="warnings"></span><span class="badge info" id="infos"></span></div><div class="table-wrap"><table><thead><tr><th>Check ID</th><th>Severity</th><th>File</th><th>Line</th><th>Description</th><th>Fix</th></tr></thead><tbody id="findings"></tbody></table><div class="empty hidden" id="clean">No security issues found.</div></div></section>
<section class="card"><details><summary>Email alerts</summary><label class="toggle"><input type="checkbox" id="emailOn"> Enable email alerts</label><div id="emailPanel" class="hidden"><div class="grid"><input id="host" placeholder="SMTP host"><input id="port" type="number" value="587" placeholder="Port"><input id="user" placeholder="Username"><input id="password" type="password" placeholder="Password"><input id="from" class="wide" placeholder="From address"><input id="to" placeholder="Recipient"><label class="toggle"><input id="tls" type="checkbox" checked> Use TLS</label></div><div class="actions"><button id="save">Save Config</button><button class="secondary" id="test">Send Test Email</button><button class="secondary" id="report" disabled>Email Report</button></div><div class="status" id="emailStatus"></div></div></details></section>
<footer>HTML Report Security Checker &mdash; github.com/zuwasi/html-report-security-checker</footer></main>
<script>
const $=id=>document.getElementById(id);let current=[];
function esc(v){const d=document.createElement('div');d.textContent=v??'';return d.innerHTML}
async function api(url,options={}){const r=await fetch(url,{headers:{'Content-Type':'application/json'},...options});let data;try{data=await r.json()}catch{data={error:'Invalid server response'}}if(!r.ok)throw new Error(data.error||`Request failed (${r.status})`);return data}
async function scan(path){$('status').textContent='Scanning...';$('scan').disabled=true;try{const directory=/[\\\/]$/.test(path);const data=await api(directory?'/api/scan-directory':'/api/scan',{method:'POST',body:JSON.stringify({path})});current=data.findings||data;render(current)}catch(e){$('status').textContent=e.message}finally{$('scan').disabled=false}}
async function scanContent(file){$('status').textContent='Scanning '+file.name+'...';$('scan').disabled=true;try{const text=await file.text();const data=await api('/api/scan-content',{method:'POST',body:JSON.stringify({filename:file.name,content:text})});current=data.findings||data;render(current)}catch(e){$('status').textContent=e.message}finally{$('scan').disabled=false}}
function render(items){const count=s=>items.filter(x=>x.severity===s).length;$('errors').textContent=`${count('error')} Errors`;$('warnings').textContent=`${count('warning')} Warnings`;$('infos').textContent=`${count('info')} Info`;$('findings').innerHTML=items.map(x=>`<tr class="${esc(x.severity)}"><td>${esc(x.check_id)}</td><td class="sev">${esc(x.severity)}</td><td>${esc(x.file_path)}</td><td>${esc(x.line_number)}</td><td>${esc(x.explanation)}</td><td>${esc(x.fix_suggestion)}</td></tr>`).join('');$('clean').classList.toggle('hidden',items.length>0);$('results').classList.remove('hidden');$('scanner').classList.add('hidden');$('report').disabled=false;$('status').textContent=''}
$('scan').onclick=()=>{const p=$('path').value.trim();if(p)scan(p);else $('status').textContent='Enter a file or directory path.'};$('path').onkeydown=e=>{if(e.key==='Enter')$('scan').click()};$('again').onclick=()=>{$('results').classList.add('hidden');$('scanner').classList.remove('hidden');$('path').focus()};
const drop=$('drop');['dragenter','dragover'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.add('over')}));['dragleave','drop'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.remove('over')}));drop.ondrop=e=>{const f=e.dataTransfer.files[0];if(f){if(f.path){$('path').value=f.path;scan(f.path)}else{scanContent(f)}}};
$('browse').onclick=()=>$('fileInput').click();
$('fileInput').onchange=e=>{const f=e.target.files[0];if(f){$('path').value=f.name;scanContent(f)}};
$('emailOn').onchange=()=>{$('emailPanel').classList.toggle('hidden',!$('emailOn').checked)};
function cfg(){return{host:$('host').value,port:Number($('port').value),user:$('user').value,password:$('password').value,from:$('from').value,tls:$('tls').checked}}
function msg(v){$('emailStatus').textContent=v}
$('save').onclick=async()=>{try{await api('/api/email-config',{method:'POST',body:JSON.stringify(cfg())});msg('Configuration saved.')}catch(e){msg(e.message)}};
$('test').onclick=async()=>{try{msg('Sending...');await api('/api/test-email',{method:'POST',body:JSON.stringify({to:$('to').value})});msg('Test email sent.')}catch(e){msg(e.message)}};
$('report').onclick=async()=>{try{msg('Sending...');await api('/api/email',{method:'POST',body:JSON.stringify({to:$('to').value,findings:current,scan_target:$('path').value})});msg('Report emailed.')}catch(e){msg(e.message)}};
api('/api/version').then(x=>$('version').textContent='v'+x.version);api('/api/config').then(c=>{if(c.configured){$('host').value=c.host||'';$('port').value=c.port||587;$('user').value=c.user||'';$('from').value=c.from||'';$('tls').checked=c.tls!==false}});
</script></body></html>'''


def _finding_dict(finding):
    """Return a JSON-safe representation containing every Finding field."""
    return {
        "check_id": finding.check_id,
        "severity": finding.severity.value,
        "file_path": str(finding.file_path),
        "line_number": finding.line_number,
        "matched_text": finding.matched_text,
        "explanation": finding.explanation,
        "fix_suggestion": finding.fix_suggestion,
    }


class RequestBodyTooLarge(ValueError):
    """Raised when an API request exceeds the accepted body size."""


class GUIHandler(http.server.BaseHTTPRequestHandler):
    """Serve the SPA and its local JSON API."""

    def _json(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 10 * 1024 * 1024:
            raise RequestBodyTooLarge("Request body exceeds 10 MB")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def serve_html_page(self):
        payload = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.serve_html_page()
        elif path == "/api/version":
            self._json({"version": __version__})
        elif path == "/api/config":
            config = load_config()
            self._json({
                "configured": bool(config and config.smtp_host and config.from_addr),
                "host": config.smtp_host if config else "",
                "port": config.smtp_port if config else 587,
                "user": config.smtp_user if config else "",
                "from": config.from_addr if config else "",
                "tls": config.use_tls if config else True,
            })
        else:
            self._json({"error": "Not found"}, 404)

    def do_POST(self):
        try:
            data = self._body()
            path = urlparse(self.path).path
            if path in ("/api/scan", "/api/scan-directory", "/api/scan-content"):
                if path == "/api/scan-content":
                    filename = data.get("filename", "uploaded.html")
                    content = data.get("content", "")
                    if not content:
                        self._json({"error": "No content provided"}, 400)
                        return
                    checker = Checker()
                    findings = checker.check_content(content, Path(filename))
                    self._json({"findings": [_finding_dict(item) for item in findings]})
                else:
                    target = Path(data.get("path", "")).expanduser()
                    expected = target.is_dir() if path.endswith("directory") else target.is_file()
                    if not expected:
                        self._json({"error": "File not found"}, 404)
                        return
                    checker = Checker()
                    findings = checker.check_directory(target) if target.is_dir() else checker.check_file(target)
                    self._json({"findings": [_finding_dict(item) for item in findings]})
            elif path == "/api/email-config":
                config = EmailConfig(
                    smtp_host=data.get("host", ""),
                    smtp_port=int(data.get("port", 587)),
                    smtp_user=data.get("user", ""),
                    smtp_password=data.get("password", ""),
                    from_addr=data.get("from", ""),
                    use_tls=data.get("tls", True),
                )
                save_config(config)
                self._json({"ok": True})
            elif path == "/api/test-email":
                config = load_config()
                if config is None:
                    raise ValueError("SMTP configuration is incomplete")
                recipient = data.get("to", "")
                if not recipient:
                    raise ValueError("Recipient email is required")
                if not EmailAlert(config).send_test(recipient):
                    raise ValueError("Failed to send test email — check SMTP settings")
                self._json({"ok": True})
            elif path == "/api/email":
                config = load_config()
                if config is None:
                    raise ValueError("SMTP configuration is incomplete")
                recipient = data.get("to", "")
                if not recipient:
                    raise ValueError("Recipient email is required")
                findings = data.get("findings", [])
                scan_target = data.get("scan_target", data.get("path", ""))
                if not EmailAlert(config).send_report(findings, scan_target, recipient):
                    raise ValueError("Failed to send email report — check SMTP settings")
                self._json({"ok": True})
            else:
                self._json({"error": "Not found"}, 404)
        except RequestBodyTooLarge as exc:
            self._json({"error": str(exc)}, 413)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json({"error": "Invalid JSON request"}, 400)
        except (OSError, ValueError) as exc:
            self._json({"error": str(exc)}, 400)

    def log_message(self, format, *args):
        """Suppress the default per-request console logging."""


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTP server whose request workers do not delay shutdown."""

    daemon_threads = True
    allow_reuse_address = True


def start_gui(port=0, open_browser=True):
    """Start the local web GUI and serve until interrupted."""
    server = ThreadingHTTPServer(("localhost", port), GUIHandler)
    actual_port = server.server_address[1]
    url = f"http://localhost:{actual_port}"
    print(f"HTML Report Security Checker: {url}")
    if open_browser:
        threading.Timer(0.25, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HTML Report Security Checker.")
    finally:
        server.server_close()


if __name__ == "__main__":
    start_gui()
