#!/usr/bin/env bash
set -euo pipefail

# ---- Tunables ----
GUID="11111111-1111-1111-1111-111111111111"   # change if you want to test different tokens
PORT="8002"                                    # change to 80/443 only if you know what you're doing

echo "[*] Installing Python and creating service user ..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv

# Create a dedicated service user
if ! id -u lemurloot >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin lemurloot
fi

echo "[*] Laying down files under /opt/lemurloot-mock ..."
sudo mkdir -p /opt/lemurloot-mock
sudo chown lemurloot:lemurloot /opt/lemurloot-mock

# Write the mock server
sudo tee /opt/lemurloot-mock/lemurloot_mock.py >/dev/null <<'PY'
#!/usr/bin/env python3
import os, io, gzip
from http.server import BaseHTTPRequestHandler, HTTPServer

GUID = os.environ.get("GUID", "11111111-1111-1111-1111-111111111111")
PORT = int(os.environ.get("PORT", "8000"))

class H(BaseHTTPRequestHandler):
    def do_GET(self):  self._handle()
    def do_POST(self): self._handle()

    def log(self, msg):
        print(f"[{self.client_address[0]}] {msg}", flush=True)

    def _handle(self):
        # Check GUID header
        guid = self.headers.get('X-siLock-Comment','')
        if guid != GUID:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
            self.log(f"404 {self.command} {self.path} (missing/invalid GUID '{guid}')")
            return

        # Build payload based on Step headers
        step1 = self.headers.get('X-siLock-Step1')
        step2 = self.headers.get('X-siLock-Step2')
        step3 = self.headers.get('X-siLock-Step3')

        if step1 == "-1":
            body_txt = "AZURE_SETTINGS;Files:list;Folders:list;Owners:list"
        elif step1 == "-2":
            body_txt = "DELETE_USER RealName='Health Check Service'"
        elif step2 or step3:
            body_txt = f"FETCH_FILE fileid={step2 or 'NULL'} folderid={step3 or 'NULL'}"
        else:
            body_txt = "CREATE_OR_USE_ACCOUNT RealName='Health Check Service'"

        # Gzip the body to emulate LEMURLOOT behavior
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            gz.write(body_txt.encode())

        body = buf.getvalue()

        # Success headers (handshake + gzip)
        self.send_response(200)
        self.send_header('X-siLock-Comment','comment')
        self.send_header('Content-Encoding','gzip')
        self.send_header('Content-Type','application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.log(f"200 {self.command} {self.path} GUID_OK Steps: "
                 f"Step1={step1} Step2={step2} Step3={step3}")

def main():
    bind = ('0.0.0.0', PORT)
    print(f"[*] LEMURLOOT mock listening on {bind[0]}:{bind[1]} with GUID={GUID}", flush=True)
    HTTPServer(bind, H).serve_forever()

if __name__ == "__main__":
    main()
PY

sudo chmod 0755 /opt/lemurloot-mock/lemurloot_mock.py
sudo chown lemurloot:lemurloot /opt/lemurloot-mock/lemurloot_mock.py

# Optional venv (no external deps, but keeps things clean)
if [ ! -d /opt/lemurloot-mock/venv ]; then
  sudo python3 -m venv /opt/lemurloot-mock/venv
  sudo /opt/lemurloot-mock/venv/bin/python -m pip install --upgrade pip >/dev/null
fi

# systemd unit
sudo tee /etc/systemd/system/lemurloot-mock.service >/dev/null <<SERVICE
[Unit]
Description=LEMURLOOT Mock Server for Zeek Sequence Testing
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lemurloot
Group=lemurloot
Environment=GUID=${GUID}
Environment=PORT=${PORT}
ExecStart=/opt/lemurloot-mock/venv/bin/python /opt/lemurloot-mock/lemurloot_mock.py
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

echo "[*] Enabling and starting service ..."
sudo systemctl daemon-reload
sudo systemctl enable --now lemurloot-mock.service

echo "[*] Opening firewall port ${PORT} (if ufw is active) ..."
if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow ${PORT}/tcp || true
fi

echo "[*] Status:"
sudo systemctl --no-pager --full status lemurloot-mock.service || true

echo
echo "[*] Done. Find the Ubuntu VM IP (e.g.,: ip -4 addr show). The server is on port ${PORT}."
