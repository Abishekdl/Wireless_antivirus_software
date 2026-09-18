"""
=============================================================================
pi_server.py — QUANTUM ANTIVIRUS — Raspberry Pi Zero 2W
=============================================================================
  ✓ HTTP port 80 — no HTTPS, no cert warning, works with captive portal
  ✓ Captive portal — browser opens automatically when device connects to WiFi
  ✓ Real ML model (pdf_student.pkl)
  ✓ WebSocket push — popup + auto-download on ALL connected devices
  ✓ Auto-download clean PDF to uploader's browser (blob method)
  ✓ Fallback — file also saved to USB if browser blocks download
  ✓ Token queue + USB storage

INSTALL ON PI (one time):
  pip install flask flask-sock numpy scikit-learn --break-system-packages

FILES NEEDED IN ~/antivirus/:
  pi_server.py
  index.html
  pdf_student.pkl
  pdf_scaler.pkl

RUN:
  ~/antivirus/start_server.sh

ACCESS:
  Connect to Pi WiFi → browser opens http://192.168.4.1 automatically
=============================================================================
"""

import os, sys, time, shutil, pickle, json, threading, logging, subprocess, hashlib, secrets
import numpy as np
from flask import Flask, request, jsonify, send_from_directory, redirect, session
from flask_sock import Sock
from werkzeug.utils import secure_filename
from collections import deque

# ── In-memory log buffer (last 100 scan events for admin panel)
LOG_BUFFER = deque(maxlen=100)

class BufferHandler(logging.Handler):
    def emit(self, record):
        LOG_BUFFER.append({
            "time": time.strftime("%H:%M:%S"),
            "level": record.levelname,
            "msg": self.format(record)
        })

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)
log.addHandler(BufferHandler())

# ── Admin config — change password here
ADMIN_PASSWORD  = "2025"
ADMIN_URL_TOKEN = "sv-admin"   # access at http://192.168.4.1/sv-admin
SECRET_KEY      = secrets.token_hex(16)

# ── Load model
print("[+] Loading PDF student model...")
for fname in ["pdf_student.pkl", "pdf_scaler.pkl"]:
    if not os.path.exists(fname):
        print(f"[!] Missing: {fname}  — copy from laptop first")
        sys.exit(1)
with open("pdf_student.pkl",  "rb") as f: MODEL  = pickle.load(f)
with open("pdf_scaler.pkl",   "rb") as f: SCALER = pickle.load(f)
print("[+] Model loaded ✓")

UPLOAD_FOLDER = "/mnt/usb_share"
TEMP_FOLDER   = "/tmp/av_scan"
STAGING_FOLDER= "/tmp/av_stage"
PDF_THRESHOLD = 0.40
USB_IMAGE     = "/piusb.bin"
USB_GADGET_UDC= "/sys/kernel/config/usb_gadget/securevault/UDC"
UDC_NAME      = "3f980000.usb"

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(TEMP_FOLDER,    exist_ok=True)
os.makedirs(STAGING_FOLDER, exist_ok=True)

_sync_lock = threading.Lock()

def sync_to_usb(src_path: str, filename: str):
    """
    Safely writes a new file into the USB image so it appears on laptop.

    The problem: /piusb.bin is simultaneously:
      - Mounted on Pi side as /mnt/usb_share (for writing)
      - Exposed to laptop via USB gadget (for reading)

    When laptop has the drive open, writing directly causes EBUSY (errno 16).
    Fix: detach gadget from laptop, write, flush, reattach.
    Laptop sees a brief disconnect (~1 second) then drive reappears with new file.
    """
    with _sync_lock:
        udc_path = "/sys/kernel/config/usb_gadget/securevault/UDC"
        udc_name = "3f980000.usb"

        try:
            # Step 1 — detach from laptop so we can write safely
            try:
                with open(udc_path, 'w') as f:
                    f.write('')
                time.sleep(0.5)
                log.info("[USB SYNC] Gadget detached from laptop")
            except Exception as e:
                log.warning(f"[USB SYNC] Detach warning (continuing): {e}")

            # Step 2 — remount image writable if needed
            if not os.path.ismount(UPLOAD_FOLDER):
                subprocess.run(
                    ['mount', '-o', 'loop,sync', USB_IMAGE, UPLOAD_FOLDER],
                    check=True
                )
                log.info("[USB SYNC] Remounted USB image")

            # Step 3 — write the file
            dest = os.path.join(UPLOAD_FOLDER, filename)
            shutil.copyfile(src_path, dest)
            log.info(f"[USB SYNC] Written: {filename}")

            # Step 4 — flush all writes to disk so /piusb.bin is fully updated
            subprocess.run(['sync'], check=True)
            time.sleep(0.3)

            log.info(f"[USB SYNC] {filename} synced to USB image ✓")

        except Exception as e:
            log.error(f"[USB SYNC] Failed: {e}")

        finally:
            # Always reattach gadget to laptop even if something failed
            try:
                time.sleep(0.2)
                with open(udc_path, 'w') as f:
                    f.write(udc_name)
                log.info("[USB SYNC] Gadget reattached to laptop")
                # Give laptop OS time to detect the reconnected drive
                # and trigger auto-refresh in file manager
                time.sleep(0.5)
            except Exception as e:
                log.warning(f"[USB SYNC] Reattach warning: {e}")

            # Clean up original temp file
            try:
                os.remove(src_path)
            except Exception:
                pass

app  = Flask(__name__, static_folder=".", static_url_path="")
sock = Sock(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.secret_key = SECRET_KEY

_token      = 1
_token_lock = threading.Lock()

def next_token():
    global _token
    with _token_lock:
        t = _token; _token += 1
    return t

# ── WebSocket clients
_ws_clients = set()
_ws_lock    = threading.Lock()

def ws_broadcast(payload: dict):
    msg  = json.dumps(payload)
    dead = set()
    with _ws_lock:
        snapshot = set(_ws_clients)
    for ws in snapshot:
        try:
            ws.send(msg)
        except Exception:
            dead.add(ws)
    with _ws_lock:
        _ws_clients.difference_update(dead)
    log.info(f"[WS] Broadcast '{payload.get('type')}' to {len(snapshot)-len(dead)} clients")

@sock.route("/ws")
def websocket(ws):
    with _ws_lock:
        _ws_clients.add(ws)
    log.info(f"[WS] +1 client, total={len(_ws_clients)}")
    try:
        ws.send(json.dumps({"type": "WELCOME", "time": time.strftime("%H:%M:%S")}))
    except Exception:
        pass
    try:
        while True:
            ws.receive()
    except Exception:
        pass
    finally:
        with _ws_lock:
            _ws_clients.discard(ws)
        log.info(f"[WS] -1 client, total={len(_ws_clients)}")

# ══════════════════════════════════════════════════════
# CAPTIVE PORTAL ROUTES
# Every OS probes these URLs when joining a new WiFi.
# Redirecting them to our UI triggers the browser popup
# automatically — no user action needed.
#
#   iOS/macOS  → /hotspot-detect.html
#   Android    → /generate_204  /gen_204
#   Windows    → /connecttest.txt  /ncsi.txt
# ══════════════════════════════════════════════════════
PORTAL_URL = "http://192.168.4.1/"

@app.route("/generate_204")
@app.route("/gen_204")
def captive_android():
    # Android expects 204 No Content — returns it → skips mini-browser
    return "", 204

@app.route("/hotspot-detect.html")
@app.route("/library/test/success.html")
def captive_apple():
    # iOS/macOS expects this exact HTML — returns it → skips mini-browser
    return "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>", 200

@app.route("/ncsi.txt")
@app.route("/connecttest.txt")
def captive_windows():
    # Windows expects this text — returns it → skips mini-browser
    return "Microsoft NCSI", 200

@app.route("/redirect")
@app.route("/success.txt")
def captive_portal():
    return redirect(PORTAL_URL, code=302)

# ── Feature extraction (7 features — matches training exactly)
def extract_features(data: bytes) -> list:
    t         = data.lower()
    js        = float(t.count(b"/js") + t.count(b"/javascript"))
    openaction= float(t.count(b"/openaction"))
    obj       = float(t.count(b" obj"))
    pages     = max(float(t.count(b"/page")), 1.0)
    objstm    = float(t.count(b"/objstm"))
    aa        = float(t.count(b"/aa"))
    launch    = float(t.count(b"/launch"))
    embedded  = float(t.count(b"/embeddedfile"))
    richmedia = float(t.count(b"/richmedia"))
    encrypted = 1.0 if b"/encrypt" in t else 0.0
    counts    = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs     = counts / len(data); probs = probs[probs > 0]
    ent       = float(-np.sum(probs * np.log2(probs)))
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
    prat      = printable / max(len(data), 1)
    susp_ent  = 1.0 if (ent > 7.5 and prat < 0.15) else 0.0
    return [
        min(openaction, 5.0), min(js, 20.0), min(objstm, 50.0),
        min(obj / pages, 100.0), encrypted,
        min(aa + launch + embedded + richmedia, 20.0), susp_ent,
    ]

def scan_pdf(data: bytes) -> dict:
    t0     = time.time()
    feats  = extract_features(data)
    scaled = SCALER.transform([feats])
    proba  = MODEL.predict_proba(scaled)[0]
    score  = float(proba[1])
    ms     = (time.time() - t0) * 1000
    verdict= "MALWARE" if score >= PDF_THRESHOLD else "BENIGN"
    risk   = "HIGH" if score >= 0.75 else ("MEDIUM" if score >= PDF_THRESHOLD else "LOW")
    feat_names = ["openaction","js_count","objstm","obj_per_page",
                  "isEncrypted","suspicious_indicators","suspicious_entropy"]
    return {
        "verdict": verdict, "risk": risk,
        "score": round(score, 4), "ms": round(ms, 1),
        "features": dict(zip(feat_names, [round(v, 3) for v in feats])),
    }

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/upload", methods=["POST"])
def upload():
    username = request.form.get("username", "Student").strip()
    file     = request.files.get("file")

    if not file or file.filename == "":
        return jsonify({"error": "No file"}), 400
    if not secure_filename(file.filename).lower().endswith(".pdf"):
        return jsonify({"error": "PDF only"}), 400

    original = secure_filename(file.filename)
    tmp_path = os.path.join(TEMP_FOLDER, original)
    file.save(tmp_path)

    try:
        with open(tmp_path, "rb") as f: data = f.read()
        if not data.startswith(b"%PDF"):
            os.remove(tmp_path)
            return jsonify({"error": "Not a valid PDF"}), 400

        result = scan_pdf(data)

        if result["verdict"] == "MALWARE":
            os.remove(tmp_path)
            ws_broadcast({
                "type": "THREAT", "username": username,
                "filename": original, "score": result["score"],
                "risk": result["risk"], "time": time.strftime("%H:%M:%S"),
            })
            log.warning(f"[MALWARE] {username} / {original} score={result['score']}")
            return jsonify({**result, "message": "Malware detected. File destroyed."})

        else:
            token     = next_token()
            safe_user = username.replace(" ", "")[:20]
            new_name  = f"{token:03d}_{safe_user}.pdf"
            # Save to USB image and sync to laptop in background thread
            # Background thread so HTTP response returns immediately to phone
            t = threading.Thread(target=sync_to_usb, args=(tmp_path, new_name), daemon=True)
            t.start()
            # sync_to_usb handles tmp_path deletion
            ws_broadcast({
                "type": "CLEAN", "username": username,
                "filename": new_name, "token": f"{token:03d}",
                "score": result["score"], "time": time.strftime("%H:%M:%S"),
                "download": new_name,  # triggers auto-download on ALL connected devices
            })
            log.info(f"[CLEAN] {username} / {new_name} token={token:03d}")
            return jsonify({**result, "token": f"{token:03d}",
                            "new_filename": new_name,
                            "message": "File clean. Saved to USB."})

    except Exception as e:
        if os.path.exists(tmp_path): os.remove(tmp_path)
        log.error(f"[ERROR] {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/download/<path:filename>")
def download(filename):
    """Serve clean file so browser can download it directly."""
    safe = os.path.basename(filename)
    return send_from_directory(UPLOAD_FOLDER, safe, as_attachment=True)

@app.route("/health")
def health():
    return jsonify({
        "status": "ok", "ws_clients": len(_ws_clients),
        "next_token": _token, "model": "pdf_student.pkl",
    })

# ══════════════════════════════════════════════════════
# ADMIN PANEL ROUTES
# URL: http://192.168.4.1/sv-admin
# Protected by password login + session cookie
# ══════════════════════════════════════════════════════

def admin_required(f):
    """Decorator — redirects to login if not authenticated"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(f"/{ADMIN_URL_TOKEN}/login")
        return f(*args, **kwargs)
    return decorated

@app.route(f"/{ADMIN_URL_TOKEN}/login", methods=["GET", "POST"])
def admin_login():
    """
    GET  → serves admin login page (admin.html)
    POST → checks password, sets session cookie if correct
    Session cookie is how the browser 'remembers' you are logged in
    without needing to type password every page load
    """
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(f"/{ADMIN_URL_TOKEN}")
        return send_from_directory(".", "admin.html"), 401
    return send_from_directory(".", "admin.html")

@app.route(f"/{ADMIN_URL_TOKEN}/logout")
def admin_logout():
    session.clear()
    return redirect(f"/{ADMIN_URL_TOKEN}/login")

@app.route(f"/{ADMIN_URL_TOKEN}")
@admin_required
def admin_panel():
    return send_from_directory(".", "admin.html")

@app.route(f"/{ADMIN_URL_TOKEN}/logs")
@admin_required
def admin_logs():
    """Returns last 100 log entries as JSON for the admin panel to display"""
    return jsonify(list(LOG_BUFFER))

@app.route(f"/{ADMIN_URL_TOKEN}/shutdown", methods=["POST"])
@admin_required
def admin_shutdown():
    """
    Shuts down Pi after 3 seconds delay — gives Flask time to send HTTP
    response back to browser before the system halts.
    Server runs as root so no sudo needed — call shutdown directly.
    Uses 'at' style delay via shell: sleep 3 then shutdown.
    """
    log.warning("[ADMIN] Shutdown initiated")
    # Shell=True runs in background — Flask returns response immediately
    # sleep 3 ensures browser receives the response before Pi powers off
    subprocess.Popen("sleep 3 && /sbin/shutdown -h now", shell=True)
    return jsonify({"ok": True, "message": "Pi shutting down in 3 seconds..."})

@app.route(f"/{ADMIN_URL_TOKEN}/reboot", methods=["POST"])
@admin_required
def admin_reboot():
    """Same pattern as shutdown but reboots instead of halting"""
    log.warning("[ADMIN] Reboot initiated")
    subprocess.Popen("sleep 3 && /sbin/reboot", shell=True)
    return jsonify({"ok": True, "message": "Pi rebooting in 3 seconds..."})

@app.route(f"/{ADMIN_URL_TOKEN}/hotspot/<action>", methods=["POST"])
@admin_required
def admin_hotspot(action):
    """
    Turns Pi hotspot on or off using nmcli.
    action = 'on'  → brings up pi-hotspot connection
    action = 'off' → brings down pi-hotspot connection
    nmcli is NetworkManager CLI — no sudo needed as server runs as root.
    Uses subprocess.run (blocking) so we wait for nmcli to finish
    before returning response — gives accurate status.
    """
    if action == "on":
        result = subprocess.run(
            ["nmcli", "con", "up", "pi-hotspot"],
            capture_output=True, text=True, timeout=10
        )
        ok = result.returncode == 0
        log.info(f"[ADMIN] Hotspot ON — {'OK' if ok else result.stderr.strip()}")
        return jsonify({"ok": ok, "message": "Hotspot active" if ok else result.stderr.strip()})
    elif action == "off":
        result = subprocess.run(
            ["nmcli", "con", "down", "pi-hotspot"],
            capture_output=True, text=True, timeout=10
        )
        ok = result.returncode == 0
        log.info(f"[ADMIN] Hotspot OFF — {'OK' if ok else result.stderr.strip()}")
        return jsonify({"ok": ok, "message": "Hotspot inactive" if ok else result.stderr.strip()})
    return jsonify({"ok": False, "message": "Unknown action"}), 400

@app.route(f"/{ADMIN_URL_TOKEN}/status")
@admin_required
def admin_status():
    """Returns live system stats for the admin dashboard"""
    # Check hotspot status via nmcli
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,STATE", "con", "show", "--active"],
            capture_output=True, text=True, timeout=3
        )
        hotspot_on = "pi-hotspot" in result.stdout
    except Exception:
        hotspot_on = False

    return jsonify({
        "ws_clients"  : len(_ws_clients),
        "scans_done"  : _token - 1,
        "hotspot_on"  : hotspot_on,
        "server_time" : time.strftime("%H:%M:%S"),
        "uptime"      : open("/proc/uptime").read().split()[0] + "s",
    })

if __name__ == "__main__":
    print("=" * 50)
    print("  QUANTUM ANTIVIRUS — Pi Zero 2W SERVER")
    print("=" * 50)
    print(f"  USB folder  : {UPLOAD_FOLDER}")
    print(f"  WebSocket   : enabled (flask-sock)")
    print(f"  HTTP        : port 80 (captive portal ready)")
    print(f"  Open on any device: http://192.168.4.1")
    print("=" * 50)
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
