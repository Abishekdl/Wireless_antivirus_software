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
