# 🛰️ Skoobie Pro — Wi-Fi Security Auditor

markdown
Copy code
 ____       _     _     
/ ___| ___ | |__ (_)___ 
\___ \/ _ \| '_ \| / __|
 ___) | (_) | |_) | \__ \
|____/ \___/|_.__/|_|___/
markdown
Copy code

Skoobie Pro is an **ethical Wi-Fi auditing tool** designed for **security professionals, penetration testers, and government-authorized red teams**.  
It **does not perform password cracking** — instead, it detects wireless networks, analyzes security posture, and generates clear audit reports.  

> ⚠️ **Legal Disclaimer**:  
> Unauthorized use of Wi-Fi auditing tools is illegal.  
> Skoobie Pro must only be used on networks you **own** or have **explicit written authorization** to audit.  
> By using this software, you agree that you are solely responsible for compliance with all applicable laws.

---

## ✨ Features
- ✅ Detects Wi-Fi interfaces and monitor-mode capability
- ✅ Start/stop monitor mode with `airmon-ng`
- ✅ Scans nearby networks using `airodump-ng`
- ✅ Parses scan results into structured data
- ✅ Identifies common risks:
  - Open (unencrypted) networks
  - WEP usage (obsolete)
  - WPA / WPA2 / WPA3 configurations
  - Possible WPS-enabled APs
- ✅ Generates **reports**:
  - Human-friendly terminal tables
  - JSON export for automation
  - HTML report for easy sharing
- ✅ Enforces **legal authorization** (`--auth-file` or `--confirm-authorized`)

---

## 🛠️ Installation

### System dependencies
On Kali/Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y aircrack-ng iw net-tools python3-pip
Python dependencies
bash
Copy code
pip install rich jinja2
🚀 Usage
1. List available wireless interfaces
bash
Copy code
python3 skoobie.py --list-ifaces
2. Enable monitor mode (if supported)
bash
Copy code
sudo python3 skoobie.py -i wlan0 --start-monitor
3. Run a scan (authorized use only!)
Option A: Confirm explicitly
bash
Copy code
sudo python3 skoobie.py -i wlan0mon --scan --duration 30 --confirm-authorized "YES-AUTHORIZED"
Option B: Provide an authorization file
bash
Copy code
echo "Authorized audit of lab network" > auth.txt
sudo python3 skoobie.py -i wlan0mon --scan --duration 30 --auth-file auth.txt
4. Stop monitor mode
bash
Copy code
sudo python3 skoobie.py -i wlan0mon --stop-monitor
📊 Example Output
Terminal table
pgsql
Copy code
Skoobie Pro — Wi-Fi Audit
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ SSID      ┃ BSSID            ┃ Ch ┃ Signal┃ Security ┃ Issues                        ┃
┡━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━┻━━━━┻━━━━━━┻━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GuestNet   │ 00:11:22:33:44:55│ 6  │  -40  │ OPN      │ Open (unencrypted)            │
│ LegacyWiFi │ 11:22:33:44:55:66│ 1  │  -70  │ WEP      │ WEP in use — obsolete         │
│ CorpWiFi   │ AA:BB:CC:DD:EE:FF│ 36 │  -30  │ WPA2     │ WPA2 — strong pass required   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
Report files
skoobie_report.json

skoobie_report.html

📂 Project Structure
bash
Copy code
skoobie/
├── skoobie.py        # Main auditor script
├── README.md         # Documentation
├── requirements.txt  # Python dependencies (optional)
🧩 Roadmap
 Rogue AP detection (evil twin spotting)

 WPS detection module (safe, non-invasive)

 PMKID/handshake export only (no cracking)

 GUI frontend for SOC analysts

 Integration with SIEM (e.g., ELK/Graylog)


🤝 Contributing
Pull requests welcome!
Please ensure your contributions align with the ethical use guidelines of this project.
