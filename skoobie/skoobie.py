#!/usr/bin/env python3
"""
Skoobie Pro — Wi-Fi Security Auditor (ethical)
- Focus: detection, analysis, reporting
- DOES NOT perform password cracking
"""

import os
import sys
import argparse
import subprocess
import csv
import json
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from jinja2 import Template
except Exception:
    print("Missing Python deps: pip install rich jinja2")
    sys.exit(1)

console = Console()

# ------------------------------------------------------------------
# Logo (raw string to avoid escape warnings)
# ------------------------------------------------------------------
LOGO = r"""
 ____       _     _     
/ ___| ___ | |__ (_)___ 
\___ \/ _ \| '_ \| / __|
 ___) | (_) | |_) | \__ \
|____/ \___/|_.__/|_|___/
"""
# ------------------------------------------------------------------
# Dataclasses
# ------------------------------------------------------------------
@dataclass
class Network:
    bssid: str
    channel: Optional[int]
    privacy: str
    cipher: str
    auth: str
    power: Optional[int]
    essid: str

# ------------------------------------------------------------------
# Helpers: legal check
# ------------------------------------------------------------------
def require_authorization(args):
    if args.scan:
        # must have explicit confirmation or auth file
        if args.confirm_authorized:
            # require exact string to reduce accidental misuse
            console.print("[bold yellow]Authorization confirmation required.[/]")
            if args.confirm_authorized.strip() != "YES-AUTHORIZED":
                console.print("[red]Use --confirm-authorized \"YES-AUTHORIZED\" to confirm you have legal authorization.[/]")
                sys.exit(1)
        elif args.auth_file:
            if not Path(args.auth_file).exists():
                console.print(f"[red]Authorization file {args.auth_file} not found.[/]")
                sys.exit(1)
        else:
            console.print("[red]Error: scanning operations require --auth-file or --confirm-authorized \"YES-AUTHORIZED\"[/]")
            sys.exit(1)

# ------------------------------------------------------------------
# Interface detection
# ------------------------------------------------------------------
def list_interfaces():
    """List wireless interfaces using `iw dev` output."""
    try:
        proc = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
        out = proc.stdout
    except FileNotFoundError:
        console.print("[red]iw not found. Install `iw` (apt install iw) or use your distribution's package manager.[/]")
        return []
    interfaces = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            interfaces.append(line.split()[1])
    return interfaces

def supports_monitor_mode(interface):
    """Check (crudely) whether interface likely supports monitor mode using `iw list`."""
    try:
        proc = subprocess.run(["iw", "list"], capture_output=True, text=True, check=True)
        out = proc.stdout
    except Exception:
        return True  # assume true if we can't determine
    return "monitor" in out  # conservative check; often present for supported cards

# ------------------------------------------------------------------
# Monitor mode utilities (wrappers)
# ------------------------------------------------------------------
def start_monitor(interface):
    console.print(f"[blue]Starting monitor mode on {interface} (using airmon-ng)...[/]")
    try:
        subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
    except subprocess.CalledProcessError:
        console.print("[yellow]Warning: airmon-ng check kill failed or returned non-zero. You may need to run it yourself.[/]")
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to put {interface} into monitor mode: {e}[/]")
        raise

def stop_monitor(interface):
    console.print(f"[blue]Stopping monitor mode on {interface} (using airmon-ng)...[/]")
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True)
        subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], check=False)
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Warning stopping monitor: {e}[/]")

# ------------------------------------------------------------------
# Scanning (non-invasive): wrapper around airodump-ng that writes CSV
# ------------------------------------------------------------------
def run_airodump(interface, out_prefix="skoobie_scan", duration: Optional[int]=30):
    """
    Runs airodump-ng and writes CSV. Returns the CSV filename or raises.
    Note: requires aircrack-ng package installed.
    """
    csv_out = f"{out_prefix}-01.csv"
    tmpfile = f"{out_prefix}"
    console.print(f"[green]Running airodump-ng on {interface} for {duration}s (output -> {csv_out})[/]")
    cmd = ["sudo", "airodump-ng", "--write", tmpfile, "--output-format", "csv", interface]
    # run for a limited time
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
    # airodump sometimes appends suffix; check for file
    if not Path(csv_out).exists():
        # try to find any file starting with prefix
        for p in Path(".").glob(f"{out_prefix}*.csv"):
            return str(p)
        raise FileNotFoundError("airodump output CSV not found")
    return csv_out

# ------------------------------------------------------------------
# CSV parser for airodump-ng output
# (airodump CSV format: networks until a blank line, then clients)
# ------------------------------------------------------------------
def parse_airodump_csv(csv_path) -> List[Network]:
    nets: List[Network] = []
    with open(csv_path, newline='', errors='ignore') as fh:
        reader = csv.reader(fh)
        section = "header"
        for row in reader:
            if not row:
                # blank line toggles to clients section
                if section == "networks":
                    section = "clients"
                elif section == "header":
                    section = "networks"
                continue
            if section == "header":
                # skip header lines until empty line
                # when we hit non-empty line after header, it's probably networks header
                if "BSSID" in row and "ESSID" in row:
                    section = "networks"
                    continue
            if section == "networks":
                # airodump network rows typically: BSSID, First time seen, Last time, channel, speed, privacy, cipher, auth, power, #beacons, #IV, LAN IP, ID-length, ESSID, Key
                # We'll attempt to be robust to column counts.
                if len(row) < 14:
                    continue
                bssid = row[0].strip()
                try:
                    channel = int(row[3].strip()) if row[3].strip().isdigit() else None
                except:
                    channel = None
                privacy = row[5].strip()
                cipher = row[6].strip()
                auth = row[7].strip()
                try:
                    power = int(row[8].strip())
                except:
                    power = None
                essid = row[13].strip()
                nets.append(Network(bssid=bssid, channel=channel, privacy=privacy,
                                    cipher=cipher, auth=auth, power=power, essid=essid))
    return nets

# ------------------------------------------------------------------
# Analysis: detect risky configurations and recommend fixes
# ------------------------------------------------------------------
def analyze_networks(nets: List[Network]):
    findings = []
    for n in nets:
        risk = []
        if n.essid == "" or n.essid.lower() == "<length: 0>":
            n.essid = "<hidden>"
        # open network / OPN
        if n.privacy == "" or "OPN" in n.privacy.upper() or "NONE" in n.privacy.upper():
            risk.append("Open (unencrypted) network — data is visible to anyone")
        # WEP
        if "WEP" in n.privacy.upper() or "WEP" in n.cipher.upper():
            risk.append("WEP in use — obsolete and insecure")
        # WPA vs WPA2 vs WPA3
        if "WPA2" in n.privacy.upper() or "WPA2" in n.auth.upper():
            # ok but recommend strong passphrases and consider WPA3
            risk.append("WPA2 detected — ensure strong passphrase and consider WPA3 migration")
        elif "WPA3" in n.privacy.upper() or "SAE" in n.auth.upper():
            risk.append("WPA3/SAE detected — good (verify clients support it)")
        elif "WPA" in n.privacy.upper():
            risk.append("Legacy WPA detected — weak compared to WPA2/WPA3")
        # WPS hint: some airodump outputs may include 'WPS' in ESSID or Key field, this is heuristic
        if "WPS" in (n.essid or "").upper() or "WPS" in n.privacy.upper():
            risk.append("WPS likely enabled — consider disabling WPS (high risk)")
        if not risk:
            risk.append("No obvious issues detected from passive scan (still verify passphrase policies and firmware updates)")
        findings.append({"network": asdict(n), "issues": risk})
    return findings

# ------------------------------------------------------------------
# Reporting: terminal (rich), JSON, and HTML export
# ------------------------------------------------------------------
def report_terminal(findings):
    table = Table(title="Skoobie Pro — Wi-Fi Audit")
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID", style="magenta")
    table.add_column("Ch", justify="center")
    table.add_column("Signal", justify="center")
    table.add_column("Security", style="green")
    table.add_column("Issues", style="yellow")
    for f in findings:
        n = f["network"]
        issues = "\n".join(f["issues"])
        table.add_row(n["essid"], n["bssid"], str(n["channel"] or "-"), str(n["power"] or "-"), n["privacy"] or "-", issues)
    console.print(table)

def export_json(findings, out_path="skoobie_report.json"):
    with open(out_path, "w") as fh:
        json.dump({"generated": datetime.datetime.utcnow().isoformat(), "findings": findings}, fh, indent=2)
    console.print(f"[green]Saved JSON report to {out_path}[/]")

HTML_TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"/><title>Skoobie Pro Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f7f7f7;padding:20px}
table{border-collapse:collapse;width:100%;background:white}
th,td{border:1px solid #ddd;padding:8px}
th{background:#222;color:white}
.issue{color:#a00}
</style>
</head>
<body>
<h1>Skoobie Pro — Wi-Fi Audit Report</h1>
<p>Generated: {{ generated }}</p>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Signal</th><th>Security</th><th>Issues</th></tr>
{% for f in findings %}
<tr>
  <td>{{ f.network.essid }}</td>
  <td>{{ f.network.bssid }}</td>
  <td>{{ f.network.channel or "-" }}</td>
  <td>{{ f.network.power or "-" }}</td>
  <td>{{ f.network.privacy or "-" }}</td>
  <td class="issue">{% for i in f.issues %}{{ i }}<br/>{% endfor %}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

def export_html(findings, out_path="skoobie_report.html"):
    tpl = Template(HTML_TEMPLATE)
    rendered = tpl.render(generated=datetime.datetime.utcnow().isoformat(), findings=findings)
    with open(out_path, "w") as fh:
        fh.write(rendered)
    console.print(f"[green]Saved HTML report to {out_path}[/]")

# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(prog="Skoobie Pro", description="Wi-Fi Security Auditor (ethical)")
    parser.add_argument("-i", "--interface", help="Wireless interface (e.g., wlan0 or wlan0mon)", default=None)
    parser.add_argument("--list-ifaces", action="store_true", help="List wireless interfaces")
    parser.add_argument("--start-monitor", action="store_true", help="Use airmon-ng to start monitor mode")
    parser.add_argument("--stop-monitor", action="store_true", help="Use airmon-ng to stop monitor mode")
    parser.add_argument("--scan", action="store_true", help="Scan networks (requires authorization)")
    parser.add_argument("--duration", type=int, default=25, help="Scan duration seconds")
    parser.add_argument("--auth-file", help="Path to signed authorization file (required for scanning)")
    parser.add_argument("--confirm-authorized", help="Explicit confirmation: set to 'YES-AUTHORIZED' to proceed", default=None)
    parser.add_argument("--out-json", help="Write JSON report to file", default=None)
    parser.add_argument("--out-html", help="Write HTML report to file", default=None)
    parser.add_argument("--no-monitor-required", action="store_true", help="Allow scan in managed mode (best-effort)")
    args = parser.parse_args()

    print(LOGO)
    if args.list_ifaces:
        ifaces = list_interfaces()
        console.print("[bold]Detected wireless interfaces:[/]")
        for i in ifaces:
            console.print(f" - {i}")
        return

    if args.start_monitor or args.stop_monitor or args.scan:
        if not args.interface:
            console.print("[red]Error: --interface is required for monitor operations[/]")
            return

    # Guard: require authorization for scan
    require_authorization(args)

    if args.start_monitor:
        start_monitor(args.interface)
    if args.stop_monitor:
        stop_monitor(args.interface)

    if args.scan:
        # run airodump and parse
        try:
            csv_file = run_airodump(args.interface, duration=args.duration)
        except FileNotFoundError as e:
            console.print(f"[red]Scan failed: {e}[/]")
            return
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/]")
            return

        networks = parse_airodump_csv(csv_file)
        findings = analyze_networks(networks)
        report_terminal(findings)

        out_json = args.out_json or "skoobie_report.json"
        out_html = args.out_html or "skoobie_report.html"
        export_json(findings, out_json)
        export_html(findings, out_html)

if __name__ == "__main__":
    main()

