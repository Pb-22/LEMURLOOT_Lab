```markdown
# LEMURLOOT Emulation & Zeek Detection (Copy‑Paste Lab)

Hands‑on lab to **emulate LEMURLOOT‑style traffic** (as observed in MOVEit incidents) and **detect it with Zeek** using a short, high‑signal policy script.

This repo includes:

- `setup_lemurloot_server.sh` — Ubuntu script to install a tiny mock server as a **systemd** service.
- `lemurloot_test.ps1` — Windows PowerShell harness that sends the **handshake** and **command** headers.
- `LEMURLOOT.zeek` — Zeek policy script that raises two notices:
  - `LEMURLOOT_Handshake`
  - `LEMURLOOT_CmdGzip`

> **Lab use only.** The mock server is intentionally minimal and for contained testing—do not expose it to untrusted networks.

---

## How it works (short version)

The original LEMURLOOT web‑shell communicates via **HTTP headers**:

- Client sends a **GUID** in header `X-siLock-Comment`.
- If correct, the server **echoes** `X-siLock-Comment: comment` — this is the **handshake**.
- “Commands” ride in headers `X-siLock-Step1`, `X-siLock-Step2`, `X-siLock-Step3`.
- Responses are **gzip** encoded.

Our mock server reproduces these behaviors. The Zeek script watches HTTP headers and raises notices:

- **Handshake** notice when the echo (`comment`) is seen after a GUID.
- **CmdGzip** notice when Step headers are observed and the response is gzip.

---

## What’s inside

```

.
├─ LEMURLOOT.zeek              # Zeek policy script (detector)
├─ lemurloot\_test.ps1          # Windows traffic generator
└─ setup\_lemurloot\_server.sh   # Ubuntu mock server installer (systemd: lemurloot-mock.service)

````

---

## Prerequisites

**Ubuntu VM (server side)**
- Ubuntu 20.04 / 22.04
- `sudo` access
- Port **8002** reachable from your Windows host

**Windows (client side)**
- Windows 10+ (PowerShell + `curl.exe` available by default)
- Network access to the Ubuntu VM

**Optional (analysis)**
- Wireshark (to capture and inspect the PCAP)
- Zeek (local) or access to [try.zeek.org](https://try.zeek.org/) to test the script offline

---

## Quick start

### 1) Install & start the mock server (Ubuntu)

```bash
# On the Ubuntu VM
sudo bash setup_lemurloot_server.sh
````

What it does:

* Installs Python (if needed)
* Writes `/opt/lemurloot/mock_lemurloot_server.py`
* Registers **systemd** service **`lemurloot-mock.service`**
* Listens on `0.0.0.0:8002/human2.aspx`
* Requires header `X-siLock-Comment: 11111111-1111-1111-1111-111111111111`

Check status/logs:

```bash
systemctl status lemurloot-mock.service
journalctl -u lemurloot-mock.service -n 50 --no-pager
```

---

### 2) Generate traffic (Windows)

> **Edit the script first:** set `$S` to your **Ubuntu VM IP**.

```powershell
# In lemurloot_test.ps1
$S = "<YOUR_UBUNTU_SERVER_IP>"     # <-- change me
$G = "11111111-1111-1111-1111-111111111111"
$URL = "http://$S`:8002/human2.aspx"

Write-Host "== Probe (404 expected) ==" -ForegroundColor Cyan
curl.exe -i $URL

Write-Host "`n== Handshake-only ==" -ForegroundColor Cyan
curl.exe -i -H "X-siLock-Comment: $G" $URL

Write-Host "`n== Handshake + Step1 = -1 ==" -ForegroundColor Cyan
curl.exe -i -X POST -H "X-siLock-Comment: $G" -H "X-siLock-Step1: -1" $URL

Write-Host "`n== Delete-user (Step1 = -2) ==" -ForegroundColor Cyan
curl.exe -i -X POST -H "X-siLock-Comment: $G" -H "X-siLock-Step1: -2" $URL

Write-Host "`n== File fetch (Step2/Step3) ==" -ForegroundColor Cyan
curl.exe -i -X POST -H "X-siLock-Comment: $G" -H "X-siLock-Step2: 123" -H "X-siLock-Step3: 456" $URL
```

You should see `HTTP/1.0 200 OK` responses. For valid handshakes, the response includes the header:

```
X-siLock-Comment: comment
```

and the body is `Content-Encoding: gzip`.

---

### 3) (Optional) Validate with Wireshark

Use one of these **display filters**:

**Targeted** (path/headers/gzip + your server IP):

```
ip.addr == <YOUR_UBUNTU_SERVER_IP> && http &&
(http.request.uri == "/human2.aspx" ||
 http contains "X-siLock-Comment" ||
 http contains "X-siLock-Step" ||
 http.content_encoding == "gzip")
```

**Port‑centric** (if you kept 8002):

```
tcp.port == 8002 && http
```

Look for:

* Client request with `X-siLock-Comment: <GUID>`
* Server response echoing `X-siLock-Comment: comment`
* POSTs with `X-siLock-Step*`
* Responses with `Content-Encoding: gzip`

---

## Detect it with Zeek

### Option A — try.zeek.org (no install)

1. Open [try.zeek.org](https://try.zeek.org/).
2. Paste the contents of **`LEMURLOOT.zeek`** into the left pane.
3. Upload your PCAP from Wireshark (the traffic you just generated).
4. Run the script.
5. Open **`notice.log`** — you should see `LEMURLOOT_Handshake` and/or `LEMURLOOT_CmdGzip`.

If HTTP wasn’t recognized on port 8002 (e.g., very short PCAP):

* In `LEMURLOOT.zeek`, set:

  ```zeek
  option LEMURLOOT::force_http_port_registration = T;
  ```

  This forces the HTTP analyzer on a small curated list of ports (including 8002).

### Option B — Local Zeek

```bash
# Run Zeek against a pcap and load the detector
zeek -Cr your-capture.pcap LEMURLOOT.zeek

# View the results
cat notice.log
```

A typical notice line will include fields like: `ts`, `uid`, `id.orig_h`, `id.resp_h`, `note`, `msg`, etc.

---

## Script options (in `LEMURLOOT.zeek`)

* `option alert_on_handshake_only = T &redef;`
  Raise a notice as soon as the server echoes `X-siLock-Comment: comment`.

* `option force_http_port_registration = F &redef;`
  When set to `T`, forces HTTP analysis on a **short list of ports** (80, 8080, 8002, …) via

  ```zeek
  const forced_http_ports: set[port] = { 80/tcp, 8080/tcp, 8088/tcp, 8880/tcp, 8881/tcp, 8888/tcp,
                                         8010/tcp, 8020/tcp, 8021/tcp, 8028/tcp, 8002/tcp } &redef;
  ```

* De‑duping: both notice types are suppressed for **5 minutes** by default:

  ```zeek
  redef Notice::type_suppression_intervals += {
      [LEMURLOOT_Handshake] = 5mins,
      [LEMURLOOT_CmdGzip]   = 5mins
  };
  ```

> **Terminology note:** This is a **Zeek policy script** (it encodes *what to alert and when*), but in the README we simply call it a “script.”

---

## Cleanup (Ubuntu mock server)

Because the setup script installed a **systemd** service (`lemurloot-mock.service`), stopping/removing it is straightforward.

**Stop it now**

```bash
sudo systemctl stop lemurloot-mock.service
```

**Prevent it from starting on boot (optional)**

```bash
sudo systemctl disable lemurloot-mock.service
```

**Verify it’s really stopped**

```bash
systemctl is-active lemurloot-mock.service   # should print "inactive"
sudo ss -ltnp | grep :8002 || echo "Port 8002 is closed"
# or
sudo lsof -i :8002 || echo "Nothing is listening on 8002"
```

**Peek at recent service logs (optional)**

```bash
journalctl -u lemurloot-mock.service -n 50 --no-pager
```

**Full uninstall (optional)**

```bash
# Stop and disable
sudo systemctl stop lemurloot-mock.service
sudo systemctl disable lemurloot-mock.service

# Remove the unit and reload systemd
sudo rm /etc/systemd/system/lemurloot-mock.service
sudo systemctl daemon-reload

# Remove the server files
sudo rm -rf /opt/lemurloot

# Remove the service account (only if used solely for this lab)
sudo userdel -r lemur || true
```

**Re‑enable later**

```bash
sudo systemctl enable --now lemurloot-mock.service
```

---

## Troubleshooting

* **No responses from the server**

  * Verify the Ubuntu VM IP and Windows can reach `IP:8002`.
  * Check the service is active: `systemctl status lemurloot-mock.service`.
  * Confirm the path is **`/human2.aspx`**.

* **Handshake fails**

  * Ensure `X-siLock-Comment: 11111111-1111-1111-1111-111111111111` is present.
  * The probe without header should return `404` (as designed).

* **Zeek didn’t log notices**

  * Confirm your PCAP includes the handshake and/or Step headers + `Content-Encoding: gzip`.
  * If HTTP wasn’t recognized on port 8002, set `force_http_port_registration = T`.

* **Wireshark filter shows nothing**

  * Use the port‑centric filter first: `tcp.port == 8002 && http`.
  * If you changed ports, update the filter accordingly.

---

## Reference

* Google Cloud / Mandiant: **Zero‑Day Vulnerability in MOVEit Transfer Exploited for Data Theft**
  [https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft)

---

## License

MIT (suggested). Feel free to replace with your preferred license and include a `LICENSE` file.

---

## Acknowledgments

Inspired by public reporting on MOVEit/LEMURLOOT behavior and built to help practitioners practice **sequence‑based detection** with Zeek.

```

