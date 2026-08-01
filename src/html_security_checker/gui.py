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
.drop{margin-top:16px;padding:30px;border:2px dashed #334155;border-radius:14px;text-align:center;color:var(--muted);transition:.2s}.drop.over{border-color:var(--cyan);background:#00d9ff0a}.hint,.status{color:var(--muted);font-size:.9rem}.status{min-height:1.2em;margin:12px 0 0}.badges{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.badge{border-radius:99px;padding:7px 12px;font-weight:700;cursor:pointer;opacity:.4;transition:.15s}.badge.active{opacity:1}.badge:hover{filter:brightness(1.15)}.badge .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}.error{background:#ef444422;color:#fca5a5}.error .dot{background:#ef4444}.warning{background:#f59e0b22;color:#fcd34d}.warning .dot{background:#f59e0b}.info{background:#3b82f622;color:#93c5fd}.info .dot{background:#3b82f6}
.table-wrap{overflow:auto;border-radius:12px;border:1px solid var(--line)}table{border-collapse:collapse;width:100%;min-width:850px}th,td{text-align:left;padding:11px;border-bottom:1px solid #263144;vertical-align:top}th{background:#162033;color:var(--cyan);position:sticky;top:0}tr.error td{background:#ef44440c}tr.warning td{background:#f59e0b0c}tr.info td{background:#3b82f60c}.sev{text-transform:uppercase;font-weight:800}.empty{text-align:center;color:var(--green);padding:32px}.hidden{display:none!important}
details summary{cursor:pointer;font-weight:700;color:var(--cyan)}.toggle{display:flex;gap:8px;align-items:center;margin:16px 0}.toggle input{width:auto}.grid{display:grid;grid-template-columns:2fr 1fr 2fr;gap:12px}.grid .wide{grid-column:span 2}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}footer{text-align:center;color:#64748b;margin-top:28px;font-size:.85rem}
@media(max-width:700px){.row{align-items:stretch;flex-direction:column}.grid{grid-template-columns:1fr}.grid .wide{grid-column:auto}.wrap{padding-top:22px}.card{padding:15px}}
.modal{display:none;position:fixed;inset:0;background:#000a;z-index:100;align-items:center;justify-content:center}.modal.open{display:flex}.modal-card{background:var(--panel);border:1px solid var(--line);border-radius:16px;width:min(900px,94%);max-height:86vh;display:flex;flex-direction:column;box-shadow:0 24px 70px #0008}.modal-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--line)}.modal-head h3{margin:0;font-size:1rem;color:var(--cyan)}.modal-body{flex:1;overflow:auto;padding:16px 20px}.modal-foot{display:flex;gap:10px;justify-content:flex-end;padding:12px 20px;border-top:1px solid var(--line)}.editor{width:100%;min-height:320px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:13px;line-height:1.6;color:#e5edf7;background:#080d18;border:1px solid #334155;border-radius:8px;padding:12px;resize:vertical;tab-size:2;white-space:pre;overflow:auto}.editor:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #00d9ff18}.modal-info{color:var(--muted);font-size:.85rem;margin-bottom:10px;line-height:1.5}
</style></head><body><main class="wrap">
<header><h1>HTML Report Security Checker</h1><span class="version" id="version">v...</span></header>
<section class="card" id="scanner"><div class="row"><input class="path" id="path" placeholder="C:\path\to\report.html or folder"><button class="secondary" id="browse">Browse</button><button id="scan">Scan</button></div><input type="file" id="fileInput" accept=".html,.htm" style="display:none"><div class="drop" id="drop"><strong>Drop HTML files here</strong><br><span class="hint">Click Browse to pick a file, drag &amp; drop, or enter a full path above.</span></div><div class="status" id="status"></div></section>
<section class="card hidden" id="results"><div class="row"><h2 style="flex:1;margin:0">Scan Results</h2><button class="secondary" id="exportMd">Export as .md for the agent to fix</button><button class="secondary" id="again">Scan Another</button></div><div class="badges"><span class="badge error active" id="errors" data-sev="error"><span class="dot"></span></span><span class="badge warning active" id="warnings" data-sev="warning"><span class="dot"></span></span><span class="badge info active" id="infos" data-sev="info"><span class="dot"></span></div><div class="table-wrap"><table><thead><tr><th>Check ID</th><th>Severity</th><th>File</th><th>Line</th><th>Description</th><th>Fix</th></tr></thead><tbody id="findings"></tbody></table><div class="empty hidden" id="clean">No security issues found.</div></div></section>
<section class="card"><details><summary>Email alerts</summary><label class="toggle"><input type="checkbox" id="emailOn"> Enable email alerts</label><div id="emailPanel" class="hidden"><div class="grid"><input id="host" placeholder="SMTP host"><input id="port" type="number" value="587" placeholder="Port"><input id="user" placeholder="Username"><input id="password" type="password" placeholder="Password"><input id="from" class="wide" placeholder="From address"><input id="to" placeholder="Recipient"><label class="toggle"><input id="tls" type="checkbox" checked> Use TLS</label></div><div class="actions"><button id="save">Save Config</button><button class="secondary" id="test">Send Test Email</button><button class="secondary" id="report" disabled>Email Report</button></div><div class="status" id="emailStatus"></div></div></details></section>
<footer>HTML Report Security Checker &mdash; github.com/zuwasi/html-report-security-checker</footer></main>
<div class="modal" id="modal"><div class="modal-card"><div class="modal-head"><h3 id="modalTitle">Code Editor</h3><button class="secondary" id="modalClose">Close</button></div><div class="modal-body"><div class="modal-info" id="modalInfo"></div><textarea class="editor" id="editor" spellcheck="false"></textarea></div><div class="modal-foot"><button class="secondary" id="modalCancel">Cancel</button><button id="modalSave">Save Changes</button></div></div></div>
<script>
const $=id=>document.getElementById(id);let current=[];const sevs=['error','warning','info'];let activeSevs=new Set(sevs);
function esc(v){const d=document.createElement('div');d.textContent=v??'';return d.innerHTML}
async function api(url,options={}){const r=await fetch(url,{headers:{'Content-Type':'application/json'},...options});let data;try{data=await r.json()}catch{data={error:'Invalid server response'}}if(!r.ok)throw new Error(data.error||`Request failed (${r.status})`);return data}
async function scan(path){$('status').textContent='Scanning...';$('scan').disabled=true;try{const directory=/[\\\/]$/.test(path);const data=await api(directory?'/api/scan-directory':'/api/scan',{method:'POST',body:JSON.stringify({path})});current=data.findings||data;render(current)}catch(e){$('status').textContent=e.message}finally{$('scan').disabled=false}}
async function scanContent(file){$('status').textContent='Scanning '+file.name+'...';$('scan').disabled=true;try{const text=await file.text();const data=await api('/api/scan-content',{method:'POST',body:JSON.stringify({filename:file.name,content:text})});current=data.findings||data;render(current)}catch(e){$('status').textContent=e.message}finally{$('scan').disabled=false}}
function render(items){const count=s=>items.filter(x=>x.severity===s).length;sevs.forEach(s=>{const b=$(s==='error'?'errors':s==='warning'?'warnings':'infos');b.innerHTML='<span class="dot"></span>'+count(s)+' '+s.charAt(0).toUpperCase()+s.slice(1)+(count(s)===1?'':'s')});const visible=items.filter(x=>activeSevs.has(x.severity));$('findings').innerHTML=visible.map((x,i)=>`<tr class="${esc(x.severity)}" data-idx="${i}" data-path="${esc(x.file_path)}" data-line="${x.line_number}"><td>${esc(x.check_id)}</td><td class="sev">${esc(x.severity)}</td><td>${esc(x.file_path)}</td><td>${x.line_number}</td><td>${esc(x.explanation)}</td><td>${esc(x.fix_suggestion)}</td></tr>`).join('');$('findings').querySelectorAll('tr').forEach(tr=>{tr.ondblclick=()=>openEditor(tr.dataset.path,parseInt(tr.dataset.line),tr.querySelector('.sev').textContent,tr.querySelector('td').textContent)});$('clean').classList.toggle('hidden',items.length>0);$('clean').textContent=items.length>0&&visible.length===0?'No findings match the active filter.':'No security issues found.';$('results').classList.remove('hidden');$('scanner').classList.add('hidden');$('report').disabled=false;$('status').textContent=''}
$('scan').onclick=()=>{const p=$('path').value.trim();if(p)scan(p);else $('status').textContent='Enter a file or directory path.'};$('path').onkeydown=e=>{if(e.key==='Enter')$('scan').click()};$('again').onclick=()=>{$('results').classList.add('hidden');$('scanner').classList.remove('hidden');$('path').focus()};
sevs.forEach(s=>{const id=s==='error'?'errors':s==='warning'?'warnings':'infos';$(id).onclick=()=>{if(activeSevs.has(s)){activeSevs.delete(s);$(id).classList.remove('active')}else{activeSevs.add(s);$(id).classList.add('active')}render(current)}});
const drop=$('drop');['dragenter','dragover'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.add('over')}));['dragleave','drop'].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.remove('over')}));drop.ondrop=e=>{const f=e.dataTransfer.files[0];if(f){if(f.path){$('path').value=f.path;scan(f.path)}else{scanContent(f)}}};
$('browse').onclick=()=>$('fileInput').click();
$('fileInput').onchange=e=>{const f=e.target.files[0];if(f){$('path').value=f.name;scanContent(f)}};
/* Code editor modal */
let editFilePath='';
async function openEditor(filePath,lineNum,severity,checkId){if(!filePath||filePath.startsWith('uploaded')){$('modalInfo').textContent='File is not on disk (uploaded content). Cannot edit directly.';$('editor').value='';$('editor').disabled=true;$('modalSave').disabled=true;$('modalTitle').textContent=checkId+' | '+severity}else{try{const data=await api('/api/file-content',{method:'POST',body:JSON.stringify({path:filePath})});$('editor').value=data.content;$('editor').disabled=false;$('modalSave').disabled=false;editFilePath=filePath;const lines=data.content.split('\n').length;$('modalInfo').textContent='File: '+filePath+' | Line '+lineNum+' of '+lines+' | '+severity+' | '+checkId;$('modalTitle').textContent=checkId+' | '+severity+' | Line '+lineNum;const targetLine=lineNum-1;setTimeout(()=>{const ta=$('editor');const lineHeight=parseFloat(getComputedStyle(ta).lineHeight);ta.scrollTop=Math.max(0,(targetLine-5)*lineHeight);ta.setSelectionRange(0,0)},50)}catch(e){$('modalInfo').textContent='Error loading file: '+e.message;$('editor').value='';$('editor').disabled=true;$('modalSave').disabled=true}}$('modal').classList.add('open')}
function closeModal(){$('modal').classList.remove('open');$('editor').value='';editFilePath=''}
$('modalClose').onclick=closeModal;$('modalCancel').onclick=closeModal;
$('modalSave').onclick=async()=>{if(!editFilePath)return;try{await api('/api/file-save',{method:'POST',body:JSON.stringify({path:editFilePath,content:$('editor').value})});closeModal();$('status').textContent='Saved '+editFilePath.split(/[\\\/]/).pop()+' — re-scan to verify the fix.';$('status').style.color='var(--green)';setTimeout(()=>$('status').style.color='',5000)}catch(e){$('modalInfo').textContent='Save failed: '+e.message;$('modalInfo').style.color='var(--red)'}};
/* Export as Markdown */
$('exportMd').onclick=()=>{const md=exportMarkdown(current);const blob=new Blob([md],{type:'text/markdown'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='security-findings.md';a.click();URL.revokeObjectURL(a.href)};
function exportMarkdown(findings){const now=new Date().toISOString().replace('T',' ').substring(0,19);const target=$('path').value||'scan';const counts={error:0,warning:0,info:0};findings.forEach(f=>{counts[f.severity]=(counts[f.severity]||0)+1});let md='# HTML Security Check Report\n\n';md+='**Scan target:** '+target+'\n';md+='**Date:** '+now+'\n';md+='**Findings:** '+counts.error+' error(s), '+counts.warning+' warning(s), '+counts.info+' info\n\n';md+='---\n\n## Instructions for the Agent\n\n';md+='For each finding below, either:\n';md+='1. **Fix** the issue by applying the suggested fix, or\n';md+='2. **Dismiss** as false positive by adding a comment: `<!-- HSC-FP: <reason> -->`\n\n';md+='After fixing, re-scan with `html-security-checker '+target+'` to verify.\n\n---\n\n';const bySev={error:[],warning:[],info:[]};findings.forEach(f=>{bySev[f.severity].push(f)});['error','warning','info'].forEach(sev=>{if(!bySev[sev].length)return;md+='\n## '+sev.toUpperCase()+' ('+bySev[sev].length+')\n\n';bySev[sev].forEach((f,i)=>{md+='### '+(i+1)+'. ['+f.check_id+'] '+f.explanation+'\n\n';md+='- **File:** `'+f.file_path+'`\n';md+='- **Line:** '+f.line_number+'\n';md+='- **Severity:** '+f.severity+'\n';if(f.matched_text)md+='- **Matched text:** `'+f.matched_text.substring(0,100)+'`\n';md+='- **Suggested fix:** '+f.fix_suggestion+'\n';md+='\n---\n\n'})});return md}
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
            elif path == "/api/file-content":
                file_path = Path(data.get("path", "")).expanduser()
                if not file_path.is_file():
                    self._json({"error": "File not found"}, 404)
                    return
                content = file_path.read_text(encoding="utf-8")
                self._json({"content": content, "path": str(file_path)})
            elif path == "/api/file-save":
                file_path = Path(data.get("path", "")).expanduser()
                if not file_path.is_file():
                    self._json({"error": "File not found"}, 404)
                    return
                content = data.get("content", "")
                file_path.write_text(content, encoding="utf-8")
                self._json({"ok": True, "path": str(file_path)})
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
