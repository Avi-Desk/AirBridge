#!/usr/bin/env python3
"""
AirBridge single-file app (final)

- Single-instance behavior using localhost manager socket (127.0.0.1:54321).
- First launch shows a small dialog with IP:PORT; subsequent launches display "already running" dialog.
- UI fixes: hides native file input and uses a styled label button to open file chooser (removes "No file chosen").
- Same features: auth (default admin/admin), uploads, download, zip, delete, shared clipboard, HTTPS adhoc or certs.
- Packaging: pyinstaller --noconsole --onefile --name AirBridge AirBridge_single_instance.py
"""
from flask import (
    Flask, request, render_template_string, send_from_directory, jsonify,
    abort, redirect, url_for, session, send_file
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os, json, time, hashlib, qrcode
from io import BytesIO
import socket, argparse, base64, zipfile, threading, sys, traceback
import tkinter as tk
from tkinter import messagebox

# --------------------- Config ---------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
META_FILE = os.path.join(BASE_DIR, 'meta.json')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
LOG_FILE = os.path.join(BASE_DIR, 'airbridge.log')

MANAGER_HOST = '127.0.0.1'
MANAGER_PORT = 54321

SECRET_KEY = os.environ.get('FILES_SHARE_SECRET') or 'change-this-secret-for-production'
TOKEN_DEFAULT_EXPIRY = 60 * 60 * 24

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# logging helper
def log(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f'[{ts}] {msg}\\n')
    except Exception:
        pass

app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = SECRET_KEY
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --------------------- Helpers ---------------------
def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def file_metadata(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    stat = os.stat(path)
    return {
        'name': filename,
        'size': stat.st_size,
        'mtime': int(stat.st_mtime),
        'is_image': filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))
    }

def ensure_admin():
    users = load_json(USERS_FILE)
    if not users:
        admin_pw = 'admin'
        users['admin'] = generate_password_hash(admin_pw)
        save_json(USERS_FILE, users)
        log('Created default admin user with password admin')

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return '127.0.0.1'

# --------------------- UI templates (with input hidden and label button) ---------------------
INDEX_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AirBridge — Instant file & text sharing across your Wi-Fi</title>
<style>
:root{--bg:#071422;--panel:#0b2530;--accent:#2dd4bf;--muted:#8fb3c8;--text:#e6eef8}
body{margin:0;font-family:Inter,Segoe UI,Arial;background:linear-gradient(180deg,var(--bg),#031722);color:var(--text)}
header{padding:18px;background:rgba(3,6,10,.6)}
.container{max-width:1100px;margin:18px auto;padding:12px}
.brand h1{margin:0;font-size:20px}
.tag{color:var(--muted);font-size:13px;margin-top:6px}
.card{background:linear-gradient(180deg,#06202a,#041620);padding:14px;border-radius:10px;box-shadow:0 10px 30px rgba(2,6,12,.6)}
.drop{border:2px dashed rgba(255,255,255,.03);padding:18px;border-radius:10px;text-align:center}
.files{margin-top:12px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;text-align:left;border-bottom:1px solid rgba(255,255,255,.03)}
.btn{background:var(--accent);color:#012025;border:0;padding:8px 12px;border-radius:8px;cursor:pointer}
.btn2{background:transparent;border:1px solid rgba(255,255,255,.04);color:var(--muted);padding:8px 12px;border-radius:8px;cursor:pointer}
.muted{color:var(--muted)}
.thumb{height:56px;border-radius:8px;object-fit:cover}
.notice{background:#043033;padding:10px;border-radius:8px;color:#bff}
.clipboard-area{display:flex;gap:12px;align-items:flex-start}
.clipboard-area textarea{flex:1;min-height:110px;padding:10px;border-radius:8px;border:none;background:#021018;color:#dff}
.clipboard-actions{display:flex;flex-direction:column;gap:8px}
footer{padding:6px 0;text-align:center;font-size:12px;color:#8fb3c8;border-top:1px solid rgba(255,255,255,.04);margin-top:30px}
input[type="file"]{display:none !important} /* hide native file input to remove browser "Choose file" UI */
.choose-btn{display:inline-block;padding:10px 14px;border-radius:8px;background:var(--accent);color:#012025;cursor:pointer;text-decoration:none}
@media (max-width:900px){.clipboard-area{flex-direction:column}}
</style>
</head>
<body>
<header>
  <div class="container brand">
    <div>
      <h1>AirBridge — Instant file & text sharing across your Wi-Fi</h1>
      <div class="tag">Fast, secure, and link-free sharing of files and clipboard across your Wi-Fi</div>
    </div>
    <div class="right">
      <div class="muted" id="server-port">Connecting...</div>
      <button class="btn2" onclick="location.href='/admin'">Admin</button>
      <button class="btn2" onclick="logout()">Logout</button>
    </div>
  </div>
</header>

<div class="container">
  <div class="card" style="margin-bottom:12px">
    <h3 style="margin-top:0">Shared Clipboard</h3>
    <div class="clipboard-area">
      <textarea id="clipboard-text" placeholder="Paste clear text here (Ctrl+V)."></textarea>
      <div class="clipboard-actions">
        <button class="btn" onclick="saveClipboard()">Save</button>
        <button class="btn" onclick="copyClipboard()">Copy</button>
        <button class="btn" onclick="downloadClipboard()">Download</button>
        <button class="btn2" onclick="clearClipboard()">Delete</button>
      </div>
    </div>
    <div class="muted" style="margin-top:8px">Last updated: <span id="clipboard-time">—</span></div>
  </div>

  <div class="card">
    <div class="notice" id="notice">Tip: Paste files directly (Ctrl+V) or drag & drop. Uploaded files are available to devices on the same Wi-Fi.</div>
    <div style="height:12px"></div>

    <div class="drop" id="drop">
      Drop files here or
      <!-- Hidden native input; custom label triggers it -->
      <label for="fileinput" class="choose-btn">Choose files</label>
      <input id="fileinput" type="file" multiple>
    </div>

    <div id="progress"></div>
    <div class="files card" id="files" style="margin-top:12px"></div>
  </div>
</div>

<footer>Built with 💙 by Avinash · <a href="https://github.com/Avi-Desk" style="color:#2dd4bf;text-decoration:none">GitHub</a></footer>

<script>
let serverInfo = {};
async function fetchServer(){
  const res = await fetch('/server_info'); serverInfo = await res.json();
  const host = serverInfo.host || 'localhost';
  document.getElementById('server-port').innerText = `https://${host}:${serverInfo.port}` + (serverInfo.requested_port && serverInfo.requested_port!=serverInfo.port ? ` (requested ${serverInfo.requested_port})` : '');
  if(serverInfo.requested_port && serverInfo.requested_port!=serverInfo.port){
    document.getElementById('notice').innerText = 'Requested port unavailable — connected on fallback port ' + serverInfo.port;
  }
}

async function fetchClipboard(){
  const res = await fetch('/api/clipboard', {credentials: 'include'});
  if(res.status===401){ window.location='/login'; return }
  const j = await res.json();
  document.getElementById('clipboard-text').value = j.text || '';
  document.getElementById('clipboard-time').innerText = j.mtime ? new Date(j.mtime*1000).toLocaleString() : '—';
}

async function saveClipboard(){
  const txt = document.getElementById('clipboard-text').value;
  await fetch('/api/clipboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:txt}),credentials:'include'});
  fetchClipboard();
}

async function copyClipboard(){
  const txt = document.getElementById('clipboard-text').value;
  try{ await navigator.clipboard.writeText(txt); alert('Copied to clipboard'); }catch(e){ alert('Copy failed'); }
}

function downloadClipboard(){ window.location='/clipboard/download' }
async function clearClipboard(){ if(!confirm('Clear shared clipboard?')) return; await fetch('/api/clipboard',{method:'DELETE',credentials:'include'}); fetchClipboard(); }

async function fetchList(){
  const res = await fetch('/api/list', {credentials: 'include'});
  if(res.status===401){ window.location='/login'; return }
  const data = await res.json();
  const files = data.files; const el = document.getElementById('files');
  if(files.length===0){ el.innerHTML = '<div class="muted">No files uploaded yet.</div>'; return }
  let html = '<table><tr><th></th><th>Name</th><th>Size</th><th>Uploaded</th><th>Actions</th></tr>';
  for(const f of files){
    html += `<tr>`;
    html += `<td>${f.is_image?`<img src="/preview/${encodeURIComponent(f.name)}" class="thumb">`:'—'}</td>`;
    html += `<td><a href="/download/${encodeURIComponent(f.name)}">${f.name}</a></td>`;
    html += `<td class="muted">${formatBytes(f.size)}</td>`;
    html += `<td class="muted">${new Date(f.mtime*1000).toLocaleString()}</td>`;
    html += `<td>`;
    html += `<button class="btn" onclick="downloadFile('${encodeURIComponent(f.name)}')">Download</button> `;
    html += `<button class="btn" onclick="zipDownload('${encodeURIComponent(f.name)}')">ZIP</button> `;
    html += `<button class="btn2" onclick="del('${encodeURIComponent(f.name)}')">Delete</button>`;
    html += `</td>`;
    html += `</tr>`;
  }
  html += '</table>';
  el.innerHTML = html;
}

function formatBytes(bytes){ if(bytes===0) return '0 B'; const k=1024; const sizes=['B','KB','MB','GB','TB']; const i=Math.floor(Math.log(bytes)/Math.log(k)); return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+' '+sizes[i]; }

async function uploadFiles(files){
  const form = new FormData();
  for(const f of files) form.append('files', f);
  const xhr = new XMLHttpRequest();
  xhr.open('POST','/api/upload');
  xhr.withCredentials = true;
  xhr.upload.onprogress = (e)=>{ if(e.lengthComputable){ const p = Math.round((e.loaded/e.total)*100); document.getElementById('progress').innerText = `Uploading... ${p}%`; } }
  xhr.onload = ()=>{ document.getElementById('progress').innerText = ''; fetchList(); }
  xhr.send(form);
}

// drag & drop
const drop = document.getElementById('drop');
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,(ev)=>{ev.preventDefault(); drop.style.borderColor='var(--accent)'}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,(ev)=>{ev.preventDefault(); drop.style.borderColor='rgba(255,255,255,.03)'}));
drop.addEventListener('drop',(ev)=>{ const dt=ev.dataTransfer; if(dt.files.length) uploadFiles(dt.files); });

// file chooser - attach to hidden input
const fileInput = document.getElementById('fileinput');
fileInput.addEventListener('change',(ev)=>{ if(ev.target.files.length) uploadFiles(ev.target.files); });

// clipboard paste support for files
window.addEventListener('paste',(ev)=>{
  const items = ev.clipboardData.items;
  const files = [];
  for(const it of items){ if(it.kind==='file'){ const f = it.getAsFile(); files.push(f); }}
  if(files.length) uploadFiles(files);
});

async function del(name){ if(!confirm('Delete '+decodeURIComponent(name)+' ?')) return; const res=await fetch('/api/delete/'+name,{method:'POST',credentials:'include'}); if(res.ok) fetchList(); else alert('Delete failed'); }

function downloadFile(name){ window.location=`/download/${name}` }
async function zipDownload(name){ window.location=`/api/zip/${name}` }

function logout(){ fetch('/logout').then(()=>location='/login') }

fetchServer(); fetchList(); fetchClipboard(); setInterval(()=>{ fetchServer(); fetchList(); fetchClipboard(); },5000);
</script>
</body>
</html>
"""

LOGIN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AirBridge — Sign in</title>
<style>body{margin:0;font-family:Inter,Segoe UI,Arial;background:linear-gradient(180deg,#021822,#031722);color:#e6eef8}.center{display:flex;align-items:center;justify-content:center;height:100vh}.card{background:linear-gradient(180deg,#04121a,#021218);padding:22px;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.6);width:360px}input{width:100%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid #022;box-sizing:border-box}.btn{background:#2dd4bf;color:#012025;border:0;padding:10px 14px;border-radius:8px;cursor:pointer}h3{margin:0 0 6px 0}.muted{color:#89aab2;font-size:13px}.cred-note{margin-top:8px;color:#9fb0c8;font-size:12px}</style></head><body><div class="center"><div class="card"><h3>AirBridge — Sign in</h3><div class="muted">Access your local AirBridge instance</div><form method="post" action="/login" style="margin-top:12px"><label>Username</label><br><input name="user" required><br><label>Password</label><br><input name="pw" type="password" required><br><div class="cred-note">Default admin: <strong>admin</strong> / <strong>admin</strong> (change via Admin panel)</div><div style="height:10px"></div><button class="btn">Login</button></form></div></div></body></html>"""

# --------------------- Flask routes ---------------------
@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')
    return INDEX_HTML

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return LOGIN_HTML
    user = request.form.get('user'); pw = request.form.get('pw')
    users = load_json(USERS_FILE)
    if user in users and check_password_hash(users[user], pw):
        session['user'] = user
        return redirect('/')
    return 'Invalid credentials', 401

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/admin')
def admin_page():
    if session.get('user') != 'admin':
        return redirect('/login')
    return '<h3>Admin: manage users via /admin/users (GET/POST JSON)</h3>'

@app.route('/admin/users', methods=['GET','POST'])
def admin_users():
    if session.get('user') != 'admin':
        return 'unauthorized', 401
    if request.method == 'GET':
        return jsonify(load_json(USERS_FILE))
    data = request.get_json() or {}; users = load_json(USERS_FILE)
    for u, pw in data.items():
        users[u] = generate_password_hash(pw)
    save_json(USERS_FILE, users)
    return jsonify({'ok': True})

def require_auth():
    if 'user' not in session:
        abort(401)

@app.route('/api/upload', methods=['POST'])
def api_upload():
    require_auth()
    files = request.files.getlist('files')
    if not files:
        return jsonify({'ok': False, 'error': 'no files'}), 400
    saved = []
    for f in files:
        filename = secure_filename(f.filename)
        if filename == '':
            continue
        dest = os.path.join(UPLOAD_FOLDER, filename)
        base, ext = os.path.splitext(filename); i = 1
        while os.path.exists(dest):
            filename = f"{base}({i}){ext}"; dest = os.path.join(UPLOAD_FOLDER, filename); i += 1
        with open(dest, 'wb') as out:
            chunk = f.stream.read(8192)
            while chunk:
                out.write(chunk); chunk = f.stream.read(8192)
        saved.append(filename)
    return jsonify({'ok': True, 'saved': saved})

@app.route('/api/list')
def api_list():
    require_auth()
    files = []
    for fn in sorted(os.listdir(UPLOAD_FOLDER), key=lambda x: os.path.getmtime(os.path.join(UPLOAD_FOLDER, x)), reverse=True):
        files.append(file_metadata(fn))
    return jsonify({'files': files})

@app.route('/preview/<path:filename>')
def preview(filename):
    filename = os.path.basename(filename); path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(path): abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/download/<path:filename>')
def download(filename):
    filename = os.path.basename(filename); path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(path): abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/api/delete/<path:filename>', methods=['POST'])
def api_delete(filename):
    require_auth()
    filename = os.path.basename(filename); path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(path): return jsonify({'ok': False, 'error': 'not found'}), 404
    os.remove(path); meta = load_json(META_FILE); meta.get('passwords', {}).pop(filename, None); save_json(META_FILE, meta)
    return jsonify({'ok': True})

@app.route('/api/clipboard', methods=['GET','POST','DELETE'])
def api_clipboard():
    if request.method == 'GET':
        require_auth(); meta = load_json(META_FILE); clip = meta.get('clipboard', {}); return jsonify({'text': clip.get('text',''), 'mtime': clip.get('mtime')})
    if request.method == 'POST':
        require_auth(); d = request.get_json() or {}; text = d.get('text',''); meta = load_json(META_FILE); meta['clipboard'] = {'text': text, 'mtime': int(time.time())}; save_json(META_FILE, meta); return jsonify({'ok': True})
    if request.method == 'DELETE':
        require_auth(); meta = load_json(META_FILE); meta.pop('clipboard', None); save_json(META_FILE, meta); return jsonify({'ok': True})

@app.route('/clipboard/download')
def clipboard_download():
    require_auth(); meta = load_json(META_FILE); clip = meta.get('clipboard', {}); text = clip.get('text',''); buf = BytesIO(); buf.write(text.encode('utf-8')); buf.seek(0); return send_file(buf, mimetype='text/plain', as_attachment=True, download_name='clipboard.txt')

@app.route('/api/generate_link', methods=['POST'])
def api_gen_link():
    require_auth(); d = request.get_json() or {}; name = d.get('name')
    if not name: return jsonify({'ok': False}), 400
    name = os.path.basename(name); hours = d.get('hours'); password = d.get('password','')
    try: hours = int(hours)
    except Exception: hours = None
    expiry = TOKEN_DEFAULT_EXPIRY if not hours else int(hours)*3600
    if not os.path.exists(os.path.join(UPLOAD_FOLDER, name)): return jsonify({'ok': False, 'error':'missing'}), 404
    token = serializer.dumps({'name': name})
    meta = load_json(META_FILE)
    if 'passwords' not in meta: meta['passwords'] = {}
    if password.strip(): meta['passwords'][name] = hashlib.sha256(password.strip().encode()).hexdigest()
    save_json(META_FILE, meta)
    link = url_for('shared_download', token=token, _external=True)
    qr_img = qrcode.make(link); buf = BytesIO(); qr_img.save(buf,'PNG'); buf.seek(0)
    datauri = 'data:image/png;base64,' + base64.b64encode(buf.read()).decode()
    return jsonify({'ok': True, 'link': link, 'qr': datauri})

@app.route('/shared/<token>', methods=['GET','POST'])
def shared_download(token):
    try: payload = serializer.loads(token, max_age=None); name = payload.get('name')
    except SignatureExpired: return 'Link expired', 410
    except BadSignature: return 'Invalid link', 400
    meta = load_json(META_FILE); pwmap = meta.get('passwords', {})
    if name in pwmap:
        if request.method == 'GET': return '<form method="post"><input type="password" name="pw"><button>Download</button></form>'
        pw = request.form.get('pw','')
        if hashlib.sha256(pw.encode()).hexdigest() != pwmap.get(name): return 'Wrong password', 403
    if not os.path.exists(os.path.join(UPLOAD_FOLDER, name)): return 'File not found', 404
    return send_from_directory(UPLOAD_FOLDER, name, as_attachment=True)

@app.route('/api/zip/<path:name>')
def api_zip(name):
    require_auth(); name = os.path.basename(name); path = os.path.join(UPLOAD_FOLDER, name)
    if not os.path.exists(path): abort(404)
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(path, arcname=name)
    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=f'{name}.zip')

@app.route('/server_info')
def server_info():
    meta = load_json(META_FILE)
    return jsonify(meta.get('server_info', {}))

# --------------------- single-instance manager ---------------------
def manager_listener_thread(host, manager_port, server_info_provider, stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, manager_port)); s.listen(1)
    except Exception as e:
        log(f"Manager bind failed: {e}"); return
    log(f"Manager listening on {host}:{manager_port}")
    s.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    data = conn.recv(64).decode('utf-8', errors='ignore').strip()
                    if data.upper().startswith('INFO') or data.upper().startswith('GET'):
                        info = server_info_provider(); conn.sendall(info.encode('utf-8'))
                    elif data.upper().startswith('PING'):
                        conn.sendall(b'PONG')
                    else:
                        conn.sendall(b'UNKNOWN')
                except Exception:
                    pass
    finally:
        try: s.close()
        except: pass
    log("Manager listener exiting")

def query_manager(host, manager_port, timeout=1.0):
    try:
        with socket.create_connection((host, manager_port), timeout=timeout) as s:
            s.sendall(b'INFO'); s.settimeout(timeout); resp = s.recv(256)
            if not resp: return None
            return resp.decode('utf-8', errors='ignore').strip()
    except Exception:
        return None

def show_info_dialog(title, message):
    try:
        root = tk.Tk(); root.withdraw(); messagebox.showinfo(title, message, parent=root); root.destroy()
    except Exception as e:
        log(f"Dialog failed: {e}")

# --------------------- orchestration ---------------------
def find_free_port(start=3000, end=4000, requested=None):
    if requested:
        try:
            s = socket.socket(); s.bind(('0.0.0.0', requested)); s.close(); return requested
        except Exception:
            pass
    for p in range(start, end+1):
        try:
            s = socket.socket(); s.bind(('0.0.0.0', p)); s.close(); return p
        except Exception:
            continue
    raise RuntimeError('No free ports in range')

def save_server_info(host_ip, port, requested):
    meta = load_json(META_FILE); meta['server_info'] = {'host': host_ip, 'port': port, 'requested_port': requested}; save_json(META_FILE, meta)

def run_primary_instance(requested_port):
    port = find_free_port(3000, 4000, requested=requested_port)
    host_ip = get_local_ip()
    save_server_info(host_ip, port, requested_port)
    log(f"Starting AirBridge on https://{host_ip}:{port} (requested {requested_port})")

    def server_info_provider(): return f"{host_ip}:{port}"

    stop_event = threading.Event()
    mgr_thread = threading.Thread(target=manager_listener_thread, args=(MANAGER_HOST, MANAGER_PORT, server_info_provider, stop_event), daemon=True)
    mgr_thread.start()

    show_info_dialog("AirBridge — Running", f"AirBridge is running at:\\nhttps://{host_ip}:{port}\\n\\nYou can close this dialog and the server will keep running in background.")

    try:
        try:
            app.run(host='0.0.0.0', port=port, ssl_context='adhoc')
        except TypeError:
            log("adhoc SSL not available; starting HTTP fallback")
            app.run(host='0.0.0.0', port=port)
    except Exception as ex:
        log("Flask exited with exception: " + repr(ex)); traceback.print_exc()
    finally:
        stop_event.set(); log("Primary instance shutting down")

def handle_secondary_instance():
    info = query_manager(MANAGER_HOST, MANAGER_PORT, timeout=1.0)
    if info:
        show_info_dialog("AirBridge — Already running", f"AirBridge appears to be already running at:\\nhttps://{info}\\n\\nOpen that address in your browser.")
    else:
        show_info_dialog("AirBridge", "Unable to contact existing AirBridge instance. If you expected the app to be running, check logs.")
    sys.exit(0)

# --------------------- entrypoint ---------------------
if __name__ == '__main__':
    ensure_admin()
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=3000, help='Preferred port (3000-4000)')
    args = parser.parse_args()
    requested = args.port

    # check primary by trying to bind manager port
    is_primary = False
    try:
        mg = socket.socket(socket.AF_INET, socket.SOCK_STREAM); mg.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mg.bind((MANAGER_HOST, MANAGER_PORT)); mg.listen(1); mg.close(); is_primary = True
    except Exception:
        is_primary = False

    if not is_primary:
        handle_secondary_instance()
    else:
        try:
            run_primary_instance(requested)
        except KeyboardInterrupt:
            log("Interrupted, exiting"); sys.exit(0)
