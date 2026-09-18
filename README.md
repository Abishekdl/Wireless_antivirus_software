# SecureVault — Quantum Antivirus

A Raspberry Pi Zero 2 W project that scans uploaded PDFs with a saved machine-learning model and copies files classified as benign to USB storage. A Flask server provides the browser interface, WebSocket notifications, and an administration dashboard.

## Features

- PDF uploads with filename and `%PDF` header checks; requests are limited to 50 MiB, including multipart overhead.
- Seven byte-level PDF features, normalized by a saved scaler and passed to a classifier.
- `BENIGN` or `MALWARE` verdicts with a score, risk level, and inference time. Scores of 0.40 or higher are classified as malware.
- Temporary copies of flagged files are deleted. Benign files receive sequential names such as `001_Alice.pdf` and are copied to USB in a background thread.
- Scan-result notifications broadcast to connected browsers over WebSockets.
- Password-protected admin controls for status, recent logs, hotspot management, reboot, and shutdown.

## Project files

| File | Purpose |
| --- | --- |
| `pi_server.py` | Flask routes, feature extraction, model inference, USB synchronization, and admin controls |
| `index.html` | Upload interface and live scan notifications |
| `admin.html` | Admin login and dashboard |
| `files.html` | File-browser interface; its `/files/list` API is not implemented |
| `pdf_student.pkl` | Required serialized classifier |
| `pdf_scaler.pkl` | Required serialized feature scaler |
| `start_server.sh` | Launcher with hardcoded deployment and Python package paths |
| `cert.pem` | Existing certificate; unused by the HTTP server |

There is no frontend build step, dependency lockfile, model-training pipeline, or automated test suite in this snapshot.

## Raspberry Pi setup

### Prerequisites

- Raspberry Pi OS / Linux with Python 3, pip, and virtual-environment support.
- Both supplied `.pkl` files, from a trusted source. Python pickle loading can execute code.
- A configured USB mass-storage gadget named `securevault`, backed by `/piusb.bin`, with storage mounted at `/mnt/usb_share`.
- For hotspot controls, NetworkManager (`nmcli`) and a connection named `pi-hotspot`.
- For access at the default address, a configured network interface at `192.168.4.1`.

The repository does not contain hotspot, DHCP/DNS, USB-image creation, or USB-gadget provisioning scripts. Configure these separately before expecting the complete hardware workflow to work.

### Install dependencies

From the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install flask flask-sock numpy scikit-learn
```

The original launcher references Python 3.13. Exact training-time Python, NumPy, and scikit-learn versions are not documented; loading the serialized models may require matching the environment that produced them.

### Configure and start

Review the constants in `pi_server.py` before running:

| Setting | Default | Purpose |
| --- | --- | --- |
| `ADMIN_PASSWORD` | `2025` | Admin password; change before deployment |
| `ADMIN_URL_TOKEN` | `sv-admin` | Admin route prefix |
| `PDF_THRESHOLD` | `0.40` | Malware classification cutoff |
| `UPLOAD_FOLDER` | `/mnt/usb_share` | USB destination and download directory |
| `TEMP_FOLDER` | `/tmp/av_scan` | Temporary uploads |
| `STAGING_FOLDER` | `/tmp/av_stage` | Created at startup; otherwise unused |
| `USB_IMAGE` | `/piusb.bin` | USB backing image |
| `PORTAL_URL` | `http://192.168.4.1/` | Portal redirect destination |

USB synchronization also hardcodes `/sys/kernel/config/usb_gadget/securevault/UDC` and controller `3f980000.usb` inside `sync_to_usb()`. Update those values if your hardware differs; changing the similarly named module constants alone does not change that function.

Run from the project directory, because the model paths are relative to the working directory:

```bash
sudo .venv/bin/python pi_server.py
```

The current implementation uses root privileges for port 80, USB mounting and gadget operations, and system controls. It listens on `0.0.0.0:80` using Flask's development server.

Alternatively, edit `start_server.sh` to match your installation before using it. As supplied, it changes into `/home/admin/antivirus` and uses packages from `/home/admin/.local/lib/python3.13/site-packages`; it does not use the virtual environment above.

## Usage

1. Connect to the configured Pi network and open `http://192.168.4.1/` manually.
2. Enter a name, select a PDF, and submit it for scanning.
3. Read the verdict and, for benign files, the assigned token and filename.
4. Allow the background USB copy to finish before accessing the file. USB synchronization briefly detaches and reattaches the gadget.
5. Open `http://192.168.4.1/sv-admin` for administration.

A basic availability check is:

```bash
curl http://192.168.4.1/health
```

It reports server/model status, connected WebSocket clients, and the next token. It does not verify USB readiness.

## Main endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Upload page |
| POST | `/upload` | Multipart fields `username` and `file`; returns scan JSON |
| GET | `/download/<filename>` | Download a file from USB storage |
| GET | `/health` | Basic status |
| WebSocket | `/ws` | `WELCOME`, `CLEAN`, and `THREAT` notifications |
| GET | `/sv-admin` | Authenticated dashboard |
| GET, POST | `/sv-admin/login` | Login page and password submission |
| GET | `/sv-admin/logout` | Clear the admin session |
| GET | `/sv-admin/status`, `/sv-admin/logs` | Authenticated status and recent logs |
| POST | `/sv-admin/hotspot/on`, `/sv-admin/hotspot/off` | Authenticated hotspot controls |
| POST | `/sv-admin/reboot`, `/sv-admin/shutdown` | Authenticated system controls |

## Current limitations

- This is a PDF classifier prototype. A benign prediction does not guarantee a safe document. Training data, accuracy measurements, and the claimed quantum-distillation process are not provided in this repository.
- The interface includes animated scan messages and claims about sandboxing, AES-256, and zero logging. The backend implements feature-based inference and logging; it does not implement those sandboxing or encryption claims.
- The server uses HTTP and the UI uses `ws://`. The certificate is not loaded. The project directory is also configured as Flask's static directory, so project files may be publicly accessible. Restrict deployment to a controlled network until this is hardened.
- Scan notifications include usernames and filenames for all connected clients, and downloads do not require authentication.
- The upload response and notification are sent before USB synchronization completes. A successful scan response does not confirm a successful USB write; inspect server logs if a file is missing.
- Browser auto-download is not implemented in the current upload page. `files.html` requests `/files/list`, which the backend does not provide; the file-browser page cannot populate its list.
- Captive-portal probe handlers mostly return success responses. Automatic browser opening is not guaranteed; open the Pi address manually.
- Tokens, admin sessions, and the log buffer reset on restart. Reused names may overwrite earlier files, and simultaneous uploads with the same original filename share a temporary path.
- Google Fonts are requested by the HTML pages; offline clients use fallback fonts.