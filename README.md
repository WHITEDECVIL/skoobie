<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=venom&color=0:0d1117,50:1a0033,100:8800ff&height=200&section=header&text=SKOOBIE+PRO&fontSize=70&fontColor=cc44ff&fontAlignY=55&desc=Ethical%20Wi-Fi%20Security%20Auditor%20%7C%20Red%20Team%20Grade&descSize=16&descAlignY=75&descColor=ffffff&animation=twinkling" />

<br/>

![Python](https://img.shields.io/badge/Python-82%25-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117)
![HTML](https://img.shields.io/badge/HTML-18%25-E34F26?style=for-the-badge&logo=html5&logoColor=white&labelColor=0d1117)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white&labelColor=0d1117)
![Aircrack](https://img.shields.io/badge/Aircrack--ng-Powered-cc44ff?style=for-the-badge&labelColor=0d1117)
![License](https://img.shields.io/badge/License-MIT-cc44ff?style=for-the-badge&labelColor=0d1117)

<br/>

```
 ███████╗██╗  ██╗ ██████╗  ██████╗ ██████╗ ██╗███████╗    ██████╗ ██████╗  ██████╗ 
 ██╔════╝██║ ██╔╝██╔═══██╗██╔═══██╗██╔══██╗██║██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗
 ███████╗█████╔╝ ██║   ██║██║   ██║██████╔╝██║█████╗      ██████╔╝██████╔╝██║   ██║
 ╚════██║██╔═██╗ ██║   ██║██║   ██║██╔══██╗██║██╔══╝      ██╔═══╝ ██╔══██╗██║   ██║
 ███████║██║  ██╗╚██████╔╝╚██████╔╝██████╔╝██║███████╗    ██║     ██║  ██║╚██████╔╝
 ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
              [ Wireless Intelligence. Ethical by Design. ]
```

[![Stars](https://img.shields.io/github/stars/WHITEDECVIL/skoobie?style=for-the-badge&color=cc44ff&labelColor=0d1117)](https://github.com/WHITEDECVIL/skoobie/stargazers)
[![Forks](https://img.shields.io/github/forks/WHITEDECVIL/skoobie?style=for-the-badge&color=cc44ff&labelColor=0d1117)](https://github.com/WHITEDECVIL/skoobie/network)
[![Last Commit](https://img.shields.io/github/last-commit/WHITEDECVIL/skoobie?style=for-the-badge&color=cc44ff&labelColor=0d1117)](https://github.com/WHITEDECVIL/skoobie/commits)

</div>

---

## 📡 What is Skoobie Pro?

**Skoobie Pro** is a professional-grade, ethical Wi-Fi auditing tool built for **security professionals, penetration testers, and government-authorized red teams**.

It does **not** crack passwords. It **does** give you a complete wireless security posture — detecting open networks, obsolete encryption, WPS exposure, and more — then outputs clean reports for your clients or SOC.

> Think of it as your wireless threat intelligence scanner. All signal. Zero crime.

---

> ⚠️ **Legal Disclaimer:**
> Unauthorized use of Wi-Fi auditing tools is **illegal**.
> Skoobie Pro must **only** be used on networks you own or have **explicit written authorization** to audit.
> By using this software, you agree you are solely responsible for compliance with all applicable laws.

---

## ✨ Features

<table>
<tr>
<td width="50%">

**📶 Wireless Detection**
- Auto-detect Wi-Fi interfaces
- Monitor mode capability check
- Start / stop monitor mode via `airmon-ng`
- Multi-channel passive scanning

</td>
<td width="50%">

**🔍 Security Analysis**
- Open (unencrypted) network detection
- WEP obsolete encryption flagging
- WPA / WPA2 / WPA3 posture review
- WPS-enabled AP identification

</td>
</tr>
<tr>
<td width="50%">

**📊 Reporting**
- Rich terminal table output
- JSON export for automation / SIEM
- HTML report for client sharing
- Structured per-AP issue listing

</td>
<td width="50%">

**⚖️ Ethics Enforcement**
- `--confirm-authorized` flag required
- `--auth-file` for written authorization
- Zero exploitation capabilities
- Audit trail in every report

</td>
</tr>
</table>

---

## 🛠️ Installation

### System Dependencies

```bash
# Kali / Ubuntu / Debian
sudo apt update
sudo apt install -y aircrack-ng iw net-tools python3-pip
```

### Python Dependencies

```bash
pip install rich jinja2
```

---

## 🚀 Usage

### 1 — List wireless interfaces

```bash
python3 skoobie.py --list-ifaces
```

### 2 — Enable monitor mode

```bash
sudo python3 skoobie.py -i wlan0 --start-monitor
```

### 3 — Run an authorized scan

**Option A — Inline confirmation**
```bash
sudo python3 skoobie.py -i wlan0mon \
  --scan \
  --duration 30 \
  --confirm-authorized "YES-AUTHORIZED"
```

**Option B — Authorization file**
```bash
echo "Authorized audit of lab network" > auth.txt

sudo python3 skoobie.py -i wlan0mon \
  --scan \
  --duration 30 \
  --auth-file auth.txt
```

### 4 — Stop monitor mode

```bash
sudo python3 skoobie.py -i wlan0mon --stop-monitor
```

---

## 📊 Example Output

### Terminal Table

```
Skoobie Pro — Wi-Fi Audit Report
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ SSID       ┃ BSSID             ┃  Ch  ┃ Signal ┃ Security ┃ Issues                        ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GuestNet   │ 00:11:22:33:44:55 │  6   │  -40   │  OPN     │ ⚠ Open (unencrypted)          │
│ LegacyWiFi │ 11:22:33:44:55:66 │  1   │  -70   │  WEP     │ ⚠ WEP in use — obsolete       │
│ CorpWiFi   │ AA:BB:CC:DD:EE:FF │  36  │  -30   │  WPA2    │ ✓ WPA2 — strong pass required │
└────────────┴───────────────────┴──────┴────────┴──────────┴───────────────────────────────┘
```

### Report Files Generated

```
📁 output/
├── skoobie_report.json     ← structured data for SIEM / automation
└── skoobie_report.html     ← client-ready visual report
```

---

## 🗺️ Audit Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     SKOOBIE PRO WORKFLOW                        │
└─────────────────────────────────────────────────────────────────┘

  [ Authorization ]         [ Interface ]         [ Scan ]
  ┌──────────────┐         ┌────────────┐        ┌──────────────┐
  │ --auth-file  │────────►│ wlan0      │───────►│ airodump-ng  │
  │    or        │         │    ↓       │        │  passive     │
  │ --confirm-   │         │ wlan0mon   │        │  capture     │
  │ authorized   │         └────────────┘        └──────┬───────┘
  └──────────────┘                                      │
                                                        ▼
                                              [ Risk Analysis ]
                                              ┌──────────────────┐
                                              │ OPN → CRITICAL   │
                                              │ WEP → HIGH       │
                                              │ WPS → MEDIUM     │
                                              │ WPA2 → INFO      │
                                              └────────┬─────────┘
                                                       │
                                                       ▼
                                              [ Report Output ]
                                         ┌─────┬──────┬──────────┐
                                         │ TTY │ JSON │   HTML   │
                                         └─────┴──────┴──────────┘
```

---

## 📂 Project Structure

```
skoobie/
├── 📄 skoobie.py           # Core auditor — main entry point
├── 📄 README.md            # Documentation
├── 📄 requirements.txt     # Python dependencies
└── 📁 output/              # Generated reports
    ├── skoobie_report.json
    └── skoobie_report.html
```

---

## 🧩 Roadmap

| Status | Feature |
|--------|---------|
| 🔜 | Rogue AP / Evil Twin detection |
| 🔜 | WPS detection module (safe, non-invasive) |
| 🔜 | PMKID / handshake export (no cracking) |
| 🔜 | GUI frontend for SOC analysts |
| 🔜 | SIEM integration (ELK / Graylog) |
| ✅ | Monitor mode automation |
| ✅ | Multi-format report generation |
| ✅ | Authorization enforcement layer |

---

## 🤝 Contributing

Pull requests are welcome! Before submitting:

- Ensure your contribution aligns with the **ethical use guidelines** of this project
- No password cracking, deauth attacks, or exploitation features will be merged
- All new features must respect the `--confirm-authorized` enforcement model

---

## 👤 Author

<div align="center">

**Sanjay S** — *Red Teamer · Wireless Security Researcher · Bug Bounty Hunter*

[![GitHub](https://img.shields.io/badge/GitHub-WHITEDECVIL-181717?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117)](https://github.com/WHITEDECVIL)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sanjay_S-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=0d1117)](https://linkedin.com/in/sanjay-s)
[![HackerOne](https://img.shields.io/badge/HackerOne-Profile-494649?style=for-the-badge&logo=hackerone&logoColor=white&labelColor=0d1117)](https://hackerone.com)
[![Email](https://img.shields.io/badge/Gmail-sankicju@gmail.com-D14836?style=for-the-badge&logo=gmail&logoColor=white&labelColor=0d1117)](mailto:sankicju@gmail.com)

</div>

---

<div align="center">

*"The most secure network is the one whose weaknesses are known before the attacker finds them."*

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:8800ff,100:1a0033&height=100&section=footer" />

</div>
