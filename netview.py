#!/usr/bin/env python3.13

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import queue
import re
import shutil
import socket
import subprocess
import threading
import urllib.request
import urllib.error
from pathlib import Path
import tomllib
import sys
import math

from PySide6 import QtCore, QtGui, QtWidgets
import PySide6
import signal

NETVIEW_VERSION = "0.5.3"

VERBOSE = 0


def vprint(msg, level=1):
    if VERBOSE >= level:
        print(msg, flush=True)


def base_tab_name(text: str) -> str:
    return text.split(" (", 1)[0].strip()

def disclaimer_bullets_text():
    return (
        "• You are authorized to scan the local network. This is usually only the case for your own private network.\n"
        "• You are authorized to issue post scans on all devices on the local network.\n"
        "• You are aware that external servers like DNS servers and web servers are contacted and that such accesses leave traces like the IP address and time of access on these servers.\n"
        "• You understand the risks from switching remote sockets.\n"
        "Use this tool at your own risk."
    )


def load_config():
    path = Path.home() / ".netviewrc.toml"
    if not path.exists():
        vprint("[netview] config: missing")
        return {}
    try:
        cfg = tomllib.loads(path.read_text())
        vprint("[netview] config: loaded")
        return cfg
    except Exception:
        vprint("[netview] config: load failed")
        return {}


def extract_known_hosts(cfg):
    known = cfg.get("known_hosts", {})
    out = set()
    names = {}
    if "macs" in known or "names" in known:
        macs = known.get("macs", [])
        for m in macs:
            m = str(m).strip().upper().replace(":", "").replace("-", "")
            if m:
                out.add(m)
        for key, val in (known.get("names", {}) or {}).items():
            k = str(key).strip().upper().replace(":", "").replace("-", "")
            v = str(val).strip()
            if k:
                out.add(k)
                if v:
                    names[k] = v
    else:
        for key, val in known.items():
            k = str(key).strip().upper().replace(":", "").replace("-", "")
            if not k:
                continue
            out.add(k)
            name = ""
            if isinstance(val, (list, tuple)) and val:
                name = str(val[0]).strip()
            elif isinstance(val, str):
                name = val.strip()
            if name:
                names[k] = name
    return out, names


def write_config(cfg):
    path = Path.home() / ".netviewrc.toml"
    lines = []
    # known hosts
    known = cfg.get("known_hosts", {}) or {}
    macs = sorted(known.get("macs", [])) if "macs" in known else sorted(known.keys())
    names = known.get("names", {}) or {}
    lines.append("[known_hosts]")
    for m in macs:
        entry = ["", "", "", ""]
        if isinstance(known, dict) and "names" not in known:
            val = known.get(m, [])
            if isinstance(val, (list, tuple)):
                entry = [str(v) for v in list(val)[:4]]
                while len(entry) < 4:
                    entry.append("")
            elif isinstance(val, str):
                entry[0] = val
        else:
            entry[0] = str(names.get(m, "")).strip()
        key = json.dumps(str(m))
        val = json.dumps(entry)
        lines.append(f"{key} = {val}")
    lines.append("")
    # ui settings
    ui = cfg.get("ui", {})
    lines.append("[ui]")
    lines.append(f'tab = "{ui.get("tab", "Network Status")}"')
    lines.append(f'status_auto = "{ui.get("status_auto", "Off")}"')
    lines.append(f'devices_auto = "{ui.get("devices_auto", "Off")}"')
    lines.append(f'show_domain = "{ui.get("show_domain", "Off")}"')
    lines.append(f'tasmota_auto = "{ui.get("tasmota_auto", "Off")}"')
    lines.append(f'devices_sort_col = "{ui.get("devices_sort_col", "0")}"')
    lines.append(f'devices_sort_order = "{ui.get("devices_sort_order", "asc")}"')
    lines.append(f'status_sort_col = "{ui.get("status_sort_col", "0")}"')
    lines.append(f'status_sort_order = "{ui.get("status_sort_order", "asc")}"')
    lines.append(f'tasmota_sort_col = "{ui.get("tasmota_sort_col", "0")}"')
    lines.append(f'tasmota_sort_order = "{ui.get("tasmota_sort_order", "asc")}"')
    lines.append(f'prereq_sort_col = "{ui.get("prereq_sort_col", "0")}"')
    lines.append(f'prereq_sort_order = "{ui.get("prereq_sort_order", "asc")}"')
    lines.append(f'known_sort_col = "{ui.get("known_sort_col", "0")}"')
    lines.append(f'known_sort_order = "{ui.get("known_sort_order", "asc")}"')
    lines.append(f'disclaimer_ok = "{ui.get("disclaimer_ok", "Off")}"')
    lines.append(f'ping_timeout = "{ui.get("ping_timeout", "200")}"')
    lines.append(f'ping_retries = "{ui.get("ping_retries", "5")}"')
    try:
        path.write_text("\n".join(lines) + "\n")
        vprint("[netview] config: saved")
    except Exception:
        vprint("[netview] config: save failed")
        pass


def get_local_ip(timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def iter_subnet_hosts(ip_str, prefix=24):
    try:
        net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
    except ValueError:
        return []
    return [str(h) for h in net.hosts() if h.packed[-1] != 0]


def should_include_ip(ip, net=None):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.packed[-1] == 0:
        return False
    if addr.is_multicast:
        return False
    if net is not None:
        try:
            if ipaddress.ip_address(ip) == net.broadcast_address:
                return False
        except Exception:
            pass
    return True


def ping_host(ip, timeout_ms=10):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system == "darwin":
        cmd = ["ping", "-n", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", "1", ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def ping_host_timed(host, timeout_ms=1000):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    elif system == "darwin":
        cmd = ["ping", "-n", "-c", "1", "-W", str(timeout_ms), host]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", "1", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        out = proc.stdout + proc.stderr
    except Exception:
        return False, "", ""

    if proc.returncode != 0:
        return False, "", ""
    ip = ""
    for line in out.splitlines():
        if line.startswith("PING ") and "(" in line and ")" in line:
            try:
                ip = line.split("(", 1)[1].split(")", 1)[0].strip()
            except Exception:
                ip = ""
    for line in out.splitlines():
        m = re.search(r"time[=<]\s*([0-9.,]+)\s*ms", line)
        if m:
            val = m.group(1).replace(",", ".")
            return True, f"{val} ms", ip
    for line in out.splitlines():
        if "round-trip" in line or "rtt min/avg/max" in line:
            m = re.search(r"=\s*([0-9.,]+)/([0-9.,]+)/", line)
            if m:
                avg = m.group(2).replace(",", ".")
                return True, f"{avg} ms", ip
    return True, "n/a", ip


def ping_with_retries(host, timeout_ms=100, attempts=10):
    failed = 0
    last_ip = ""
    for _ in range(attempts):
        ok, ms, ip = ping_host_timed(host, timeout_ms=timeout_ms)
        last_ip = ip or last_ip
        if ok:
            return True, ms, last_ip, failed
        failed += 1
    return False, "", last_ip, failed


def parse_arp_table():
    entries = {}
    system = platform.system().lower()
    if system == "windows":
        cmd = ["arp", "-a"]
    else:
        cmd = ["arp", "-na"]

    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return entries

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "incomplete" in line.lower():
            continue

        if system == "windows":
            parts = line.split()
            if len(parts) >= 2 and "." in parts[0]:
                ip = parts[0]
                mac = format_mac(parts[1])
                if mac:
                    entries[ip] = {"name": "", "mac": mac}
        else:
            if "(" in line and ")" in line and " at " in line:
                try:
                    name_part, rest = line.split("(", 1)
                    ip = rest.split(")", 1)[0]
                    name = name_part.strip().strip("?").strip()
                    mac = ""
                    if " at " in line:
                        mac = line.split(" at ", 1)[1].split()[0]
                    mac = format_mac(mac)
                    if mac:
                        entries[ip] = {"name": name, "mac": mac}
                except Exception:
                    continue

    return entries


def get_default_gateway():
    system = platform.system().lower()
    try:
        if system == "darwin":
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if line.strip().startswith("gateway:"):
                    return line.split(":", 1)[1].strip()
        elif system == "linux":
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2).stdout
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        elif system == "windows":
            out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        return ""
    return ""


def get_dns_servers():
    system = platform.system().lower()
    servers = []
    try:
        if system == "darwin":
            out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("nameserver["):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        servers.append(parts[1].strip())
        elif system == "linux":
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        servers.append(line.split()[1])
        elif system == "windows":
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        servers.append(parts[1].strip())
    except Exception:
        return []
    # return up to two unique servers
    uniq = []
    for s in servers:
        if s and s not in uniq:
            uniq.append(s)
        if len(uniq) >= 2:
            break
    return uniq


def resolve_host(host, timeout=2.0):
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except Exception:
        return ""


def resolve_host_via_dns(host, dns_server, timeout=2.0):
    system = platform.system().lower()
    try:
        if system in ("darwin", "linux"):
            cmd = ["nslookup", host, dns_server]
        else:
            cmd = ["nslookup", host, dns_server]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Address:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        return ""
    return ""


def reverse_lookup(ip, timeout=2.0):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def tcp_connect(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def tcp_port_open(ip, port, timeout=0.2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_204_check(timeout=2.0):
    try:
        import urllib.request
        host = "connectivitycheck.gstatic.com"
        ip = resolve_host(host)
        req = urllib.request.Request(f"http://{host}/generate_204")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 204, f"HTTP {resp.status}", ip
    except Exception:
        return False, "HTTP error", ""


def http_apple_captive_check(timeout=2.0):
    try:
        import urllib.request
        host = "captive.apple.com"
        ip = resolve_host(host)
        req = urllib.request.Request(f"http://{host}/hotspot-detect.html")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200, f"HTTP {resp.status}", ip
    except Exception:
        return False, "HTTP error", ""


def http_get_json(url, timeout=2.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "netview/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def tasmota_fetch_status(ip, timeout=2.0):
    data = http_get_json(f"http://{ip}/cm?cmnd=Status%200", timeout=timeout)
    if VERBOSE >= 1:
        vprint(f"[tasmota] {ip} -> {json.dumps(data, ensure_ascii=True)}")
    if not isinstance(data, dict):
        return None
    if "Status" not in data and "StatusSTS" not in data:
        return None
    name = ""
    if "Status" in data and isinstance(data["Status"], dict):
        name = data["Status"].get("DeviceName", "")
    model = ""
    fwr = data.get("StatusFWR", {}) if isinstance(data.get("StatusFWR", {}), dict) else {}
    hw = fwr.get("Hardware", "")
    ver = fwr.get("Version", "")
    if hw and ver:
        model = f"{hw} {ver}"
    elif hw:
        model = hw
    elif ver:
        model = ver
    wifi = ""
    sts = data.get("StatusSTS", {}) if isinstance(data.get("StatusSTS", {}), dict) else {}
    wifi_info = sts.get("Wifi", {}) if isinstance(sts.get("Wifi", {}), dict) else {}
    ssid = wifi_info.get("SSId", "") or wifi_info.get("SSID", "")
    ch = wifi_info.get("Channel", "")
    rssi = wifi_info.get("RSSI", "")
    signal = wifi_info.get("Signal", "")
    if ssid:
        sig = signal if signal != "" else (f"-{rssi}" if rssi != "" else "")
        wifi = f"{ssid}/ch{ch}/{sig}" if ch != "" else f"{ssid}/{sig}"
    sts = data.get("StatusSTS", {}) if isinstance(data.get("StatusSTS", {}), dict) else {}
    power_state = sts.get("POWER", sts.get("POWER1", ""))
    power_state = str(power_state).upper() if power_state is not None else ""
    power_w = ""
    sns = data.get("StatusSNS", {}) if isinstance(data.get("StatusSNS", {}), dict) else {}
    energy = sns.get("ENERGY", {}) if isinstance(sns.get("ENERGY", {}), dict) else {}
    if "Power" in energy:
        power_w = str(energy.get("Power"))
    today = str(energy.get("Today", "")) if "Today" in energy else ""
    yesterday = str(energy.get("Yesterday", "")) if "Yesterday" in energy else ""
    total = str(energy.get("Total", "")) if "Total" in energy else ""
    return {
        "name": name,
        "model": model,
        "wifi": wifi,
        "power_state": power_state,
        "power_w": power_w,
        "today": today,
        "yesterday": yesterday,
        "total": total,
    }


def tasmota_set_power(ip, on, timeout=2.0):
    cmd = "ON" if on else "OFF"
    data = http_get_json(f"http://{ip}/cm?cmnd=Power%20{cmd}", timeout=timeout)
    if not isinstance(data, dict):
        return None
    # response contains {"POWER":"ON"} or {"POWER1":"ON"}
    val = data.get("POWER", data.get("POWER1", ""))
    return str(val).upper() if val is not None else ""


def status_tooltips():
    return {
        "Interface status": "Checks whether the local interface is up and has an IP address.\nPass: link+IP present. Fail: interface down or no IP.",
        "DHCP lease": "Checks DHCP lease info (if available).\nPass: DHCP lease found. Fail: no lease info (possible static IP or DHCP issue).",
        "Local gateway": "Pings the default gateway to verify LAN reachability.\nPass: LAN and gateway reachable. Fail: local network or gateway issue.",
        "Gateway ARP": "Verifies the gateway MAC is in ARP cache.\nPass: L2 reachability to gateway. Fail: ARP not learned.",
        "Default route": "Checks if a default route exists.\nPass: routing configured. Fail: no default route (no internet path).",
        "DNS system resolve": "Uses system resolver to resolve heise.de.\nPass: DNS resolution works. Fail: system DNS broken.",
        "DNS server 1": "Resolves heise.de using DNS server 1 explicitly.\nPass: DNS server reachable/working. Fail: DNS server unreachable or failing.",
        "DNS server 2": "Resolves heise.de using DNS server 2 explicitly.\nPass: DNS server reachable/working. Fail: DNS server unreachable or failing.",
        "Reverse lookup 1.1.1.1": "Reverse-DNS lookup for 1.1.1.1.\nPass: reverse DNS reachable. Fail: DNS reverse lookup failing.",
        "Reverse lookup 8.8.8.8": "Reverse-DNS lookup for 8.8.8.8.\nPass: reverse DNS reachable. Fail: DNS reverse lookup failing.",
        "Ping 8.8.8.8": "ICMP ping to 8.8.8.8 (Google DNS).\nPass: internet path reachable. Fail: upstream connectivity issue.",
        "Ping 1.1.1.1": "ICMP ping to 1.1.1.1 (Cloudflare DNS).\nPass: internet path reachable. Fail: upstream connectivity issue.",
        "Ping heise.de": "ICMP ping to heise.de (domain).\nPass: DNS + internet reachable. Fail: DNS or connectivity problem.",
        "TCP 443 heise.de": "TCP connect to heise.de:443.\nPass: HTTPS reachable. Fail: firewall or upstream block.",
        "HTTP 204 check": "Fetches a known 204 endpoint (Google).\nPass: no captive portal. Fail: portal or HTTP blocked.",
        "Apple captive check": "Fetches Apple's captive portal check URL.\nPass: no portal. Fail: portal or HTTP blocked.",
        "Traceroute 8.8.8.8": "Traceroute to 8.8.8.8 (first 5 hops).\nPass: route visible. Fail: routing/ICMP blocked.",
        "DNS hijack check": "Ensures heise.de resolves to a public IP.\nPass: normal DNS. Fail: private IP suggests hijack/portal.",
    }


def get_interface_info():
    local_ip = get_local_ip()
    if not local_ip:
        return {"iface": "", "ip": "", "netmask": "", "up": False}
    system = platform.system().lower()
    if system == "darwin":
        try:
            out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=2).stdout
            iface = ""
            netmask = ""
            up = False
            current = ""
            for line in out.splitlines():
                if line and not line.startswith("\t") and not line.startswith(" "):
                    current = line.split(":", 1)[0]
                if f"inet {local_ip}" in line:
                    iface = current
                    if "netmask" in line:
                        netmask = line.split("netmask", 1)[1].split()[0].strip()
                    if "status: active" in out:
                        up = True
            return {"iface": iface, "ip": local_ip, "netmask": netmask, "up": True}
        except Exception:
            return {"iface": "", "ip": local_ip, "netmask": "", "up": True}
    if system == "linux":
        try:
            out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if "inet " in line and local_ip in line:
                    parts = line.split()
                    iface = parts[1]
                    cidr = parts[3]
                    netmask = cidr.split("/", 1)[1] if "/" in cidr else ""
                    return {"iface": iface, "ip": local_ip, "netmask": netmask, "up": True}
        except Exception:
            pass
        return {"iface": "", "ip": local_ip, "netmask": "", "up": True}
    # Windows: best-effort
    return {"iface": "", "ip": local_ip, "netmask": "", "up": True}


def format_seconds(seconds):
    if seconds < 0:
        seconds = 0
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def get_dhcp_lease_info(iface):
    system = platform.system().lower()
    if system == "darwin" and iface:
        try:
            out = subprocess.run(["ipconfig", "getpacket", iface], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if "lease_time" in line:
                    raw = line.strip()
                    seconds = None
                    hex_m = re.search(r"0x[0-9a-fA-F]+", raw)
                    if hex_m:
                        try:
                            seconds = int(hex_m.group(0), 16)
                        except Exception:
                            seconds = None
                    if seconds is None:
                        dec_m = re.search(r"\\b([0-9]+)\\b", raw)
                        if dec_m:
                            try:
                                seconds = int(dec_m.group(1))
                            except Exception:
                                seconds = None
                    if seconds is not None:
                        hhmmss = format_seconds(seconds)
                        return f"{raw} ({hhmmss})"
                    return raw
                if "lease_expiration" in line:
                    return line.strip()
        except Exception:
            return "Not available"
    return "Not supported"


def traceroute_host(host, timeout=3.0):
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["tracert", "-h", "5", "-w", "1000", host]
        else:
            cmd = ["traceroute", "-n", "-m", "5", "-w", "1", host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        lines = [l for l in out.splitlines() if l.strip() and l.strip()[0].isdigit()]
        hop_count = len(lines)
        if proc.returncode != 0 or hop_count == 0:
            return False, "no hops"
        return True, f"{hop_count} hops"
    except Exception:
        return False, "timeout"


def check_port(ip, port, timeout=0.4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(ip, ports, timeout=0.4):
    open_ports = []
    for port in ports:
        if check_port(ip, port, timeout=timeout):
            open_ports.append(port)
    return open_ports


def resolve_name(ip, timeout=0.6):
    system = platform.system().lower()
    try:
        if system == "darwin":
            cmd = ["/usr/bin/dscacheutil", "-q", "host", "-a", "ip_address", ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
            for line in out.splitlines():
                if line.strip().lower().startswith("name:"):
                    return line.split(":", 1)[1].strip()
            return ""
        if system == "linux":
            cmd = ["getent", "hosts", ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
            parts = out.split()
            return parts[1] if len(parts) >= 2 else ""
        if system == "windows":
            cmd = ["nslookup", ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
            for line in out.splitlines():
                if line.strip().lower().startswith("name:"):
                    return line.split(":", 1)[1].strip()
            return ""
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def format_mac(mac):
    if not mac:
        return ""
    mac = mac.strip().lower()
    if "incomplete" in mac:
        return ""
    mac = mac.replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 1 and len(mac) == 12:
        parts = [mac[i:i+2] for i in range(0, 12, 2)]
    normalized = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if len(part) == 1:
            part = "0" + part
        elif len(part) > 2:
            part = part[-2:]
        normalized.append(part)
    if not normalized:
        return ""
    return ":".join(normalized).upper()


def load_oui_db():
    db = {}
    path = Path(__file__).parent / "ouidb.txt"
    if not path.exists():
        return db
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return db
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        prefix = parts[0].strip().upper()
        vendor = parts[1].strip()
        if prefix and vendor:
            db[prefix] = vendor
    return db


def vendor_for_mac(mac, oui_db):
    if not mac:
        return ""
    raw = format_mac(mac).replace(":", "")
    for length in (9, 7, 6):
        if len(raw) >= length:
            prefix = raw[:length]
            vendor = oui_db.get(prefix, "")
            if vendor:
                return vendor
    try:
        first_byte = int(format_mac(mac)[:2], 16)
        ig = "multicast" if (first_byte & 0x01) else "unicast"
        ul = "local" if (first_byte & 0x02) else "global"
        return f"({ig}, {ul})"
    except Exception:
        return ""


def safe_result(fut, default=None):
    try:
        return fut.result()
    except Exception:
        return default


class SortProxy(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._search = ""

    def set_search(self, text):
        self._search = (text or "").strip().lower()
        self.invalidate()

    def lessThan(self, left, right):
        col = left.column()
        lval = left.data()
        rval = right.data()

        def ip_key(val):
            try:
                return tuple(int(x) for x in str(val).split("."))
            except Exception:
                return (999, 999, 999, 999)

        def ports_key(val):
            s = str(val)
            if not s or s == "-":
                return ()
            try:
                return tuple(int(x) for x in s.split(","))
            except Exception:
                return ()

        if col == 0:
            return ip_key(lval) < ip_key(rval)
        if col == 2:
            lval = left.data(QtCore.Qt.UserRole)
            rval = right.data(QtCore.Qt.UserRole)
            try:
                return int(lval or 0) < int(rval or 0)
            except Exception:
                return False
        if col == 6:
            return ports_key(lval) < ports_key(rval)
        return str(lval).lower() < str(rval).lower()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._search:
            return True
        model = self.sourceModel()
        headers = [str(model.headerData(c, QtCore.Qt.Horizontal)) for c in range(model.columnCount())]
        web_col = None
        known_col = None
        for i, label in enumerate(headers):
            if label == "Web":
                web_col = i
            if label == "Known":
                known_col = i
        parts = []
        for col in range(model.columnCount()):
            if web_col is not None and col == web_col:
                continue
            idx = model.index(source_row, col, source_parent)
            if known_col is not None and col == known_col:
                state = model.data(idx, QtCore.Qt.UserRole)
                if state is None:
                    state = model.data(idx, QtCore.Qt.CheckStateRole)
                    parts.append("known" if state == QtCore.Qt.Checked else "unknown")
                else:
                    try:
                        parts.append("known" if int(state) == 1 else "unknown")
                    except Exception:
                        parts.append("unknown")
                continue
            val = model.data(idx, QtCore.Qt.DisplayRole)
            if val is None:
                continue
            text = str(val).strip()
            if text:
                parts.append(text)
        haystack = " ".join(parts).lower()
        return self._search in haystack


class WireCubeWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._ax = 0.0
        self._ay = 0.0
        self._az = 0.0
        self._hold_zero = False
        self._hue = 0.0
        self._bg = QtGui.QColor("#FFFFFF")
        self._line = QtGui.QColor("#6E6E73")
        self._buffer = None
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(30)

    def set_colors(self, bg, line):
        self._bg = QtGui.QColor(bg)
        self._line = QtGui.QColor(line)
        self._reset_buffer()
        self.update()

    def _tick(self):
        self._hue = (self._hue + 2.0) % 360.0
        if self._hold_zero:
            self._ax = 0.0
            self._ay = 0.0
            self._az = 0.0
            self.update()
            return
        self._ax = (self._ax + 1.3) % 360.0
        self._ay = (self._ay + 0.9) % 360.0
        self._az = (self._az + 1.1) % 360.0
        self.update()

    def _reset_buffer(self):
        if self.width() <= 0 or self.height() <= 0:
            return
        self._buffer = QtGui.QImage(self.size(), QtGui.QImage.Format_ARGB32)
        self._buffer.fill(self._bg)

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._ax = 0.0
            self._ay = 0.0
            self._az = 0.0
            self._hold_zero = True
            self._reset_buffer()
            self.update()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._hold_zero = False
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def resizeEvent(self, event):
        self._reset_buffer()
        return super().resizeEvent(event)

    def paintEvent(self, event):
        if self._buffer is None or self._buffer.size() != self.size():
            self._reset_buffer()
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        w = max(1, self.width())
        h = max(1, self.height())
        size = min(w, h) * 0.175
        cx = w * 0.5
        cy = h * 0.5
        ax = self._ax * math.pi / 180.0
        ay = self._ay * math.pi / 180.0
        az = self._az * math.pi / 180.0
        points = [
            (-1, -1, -1),
            (1, -1, -1),
            (1, 1, -1),
            (-1, 1, -1),
            (-1, -1, 1),
            (1, -1, 1),
            (1, 1, 1),
            (-1, 1, 1),
        ]

        def rotate(p):
            x, y, z = p
            cy = math.cos(ay)
            sy = math.sin(ay)
            cx = math.cos(ax)
            sx = math.sin(ax)
            cz = math.cos(az)
            sz = math.sin(az)
            x, z = x * cy + z * sy, -x * sy + z * cy
            y, z = y * cx - z * sx, y * sx + z * cx
            x, y = x * cz - y * sz, x * sz + y * cz
            return x, y, z

        def project(p):
            x, y, z = p
            d = 3.5
            scale = d / (d - z)
            return QtCore.QPointF(cx + x * size * scale, cy + y * size * scale)

        rotated = [rotate(p) for p in points]
        projected = [project(p) for p in rotated]
        edges = [
            (0, 1), (1, 2), (2, 3), (3, 0),
            (4, 5), (5, 6), (6, 7), (7, 4),
            (0, 4), (1, 5), (2, 6), (3, 7),
        ]
        faces = [
            (0, 3, 2, 1),  # back (-z)
            (4, 5, 6, 7),  # front (+z)
            (0, 4, 7, 3),  # left (-x)
            (1, 2, 6, 5),  # right (+x)
            (0, 1, 5, 4),  # bottom (-y)
            (3, 7, 6, 2),  # top (+y)
        ]
        front_edges = set()
        for face in faces:
            a, b, c, d = face
            pa = rotated[a]
            pb = rotated[b]
            pc = rotated[c]
            ab = (pb[0] - pa[0], pb[1] - pa[1], pb[2] - pa[2])
            ac = (pc[0] - pa[0], pc[1] - pa[1], pc[2] - pa[2])
            normal = (
                ab[1] * ac[2] - ab[2] * ac[1],
                ab[2] * ac[0] - ab[0] * ac[2],
                ab[0] * ac[1] - ab[1] * ac[0],
            )
            center = (
                (rotated[a][0] + rotated[b][0] + rotated[c][0] + rotated[d][0]) / 4.0,
                (rotated[a][1] + rotated[b][1] + rotated[c][1] + rotated[d][1]) / 4.0,
                (rotated[a][2] + rotated[b][2] + rotated[c][2] + rotated[d][2]) / 4.0,
            )
            view = (0.0 - center[0], 0.0 - center[1], 3.5 - center[2])
            dot = normal[0] * view[0] + normal[1] * view[1] + normal[2] * view[2]
            if dot > 0:
                front_edges.add(tuple(sorted((a, b))))
                front_edges.add(tuple(sorted((b, c))))
                front_edges.add(tuple(sorted((c, d))))
                front_edges.add(tuple(sorted((d, a))))
        buf_painter = QtGui.QPainter(self._buffer)
        buf_painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        buf_painter.setCompositionMode(QtGui.QPainter.CompositionMode_SourceAtop)
        buf_painter.fillRect(self._buffer.rect(), QtGui.QColor(self._bg.red(), self._bg.green(), self._bg.blue(), 26))
        buf_painter.setCompositionMode(QtGui.QPainter.CompositionMode_SourceOver)
        color = QtGui.QColor()
        color.setHsv(int(self._hue), 200, 220)
        pen = QtGui.QPen(color, 1.5)
        buf_painter.setPen(pen)
        for a, b in edges:
            if tuple(sorted((a, b))) not in front_edges:
                continue
            buf_painter.drawLine(projected[a], projected[b])
        buf_painter.setClipRect(self._buffer.rect())
        text_color = QtGui.QColor()
        text_color.setHsv(int((self._hue + 180.0) % 360.0), 200, 220)
        text_pen = QtGui.QPen(text_color, 1.0)
        buf_painter.setPen(text_pen)
        buf_painter.setBrush(QtCore.Qt.NoBrush)

        def strokes_for_text():
            # Simple vector strokes in a 7x7 grid, normalized to [-0.5, 0.5].
            # Each letter is defined as line segments in local 0..1 box.
            letters = {
                "n": [((0.1, 0.8), (0.1, 0.2)), ((0.1, 0.2), (0.5, 0.2)), ((0.5, 0.2), (0.5, 0.8))],
                "e": [((0.6, 0.2), (0.1, 0.2)), ((0.1, 0.2), (0.1, 0.8)), ((0.1, 0.5), (0.5, 0.5)), ((0.1, 0.8), (0.6, 0.8))],
                "t": [((0.1, 0.2), (0.9, 0.2)), ((0.5, 0.2), (0.5, 0.8))],
                "v": [((0.1, 0.2), (0.5, 0.8)), ((0.9, 0.2), (0.5, 0.8))],
                "i": [((0.5, 0.3), (0.5, 0.8)), ((0.5, 0.2), (0.5, 0.2))],
                "w": [((0.1, 0.2), (0.3, 0.8)), ((0.3, 0.8), (0.5, 0.2)), ((0.5, 0.2), (0.7, 0.8)), ((0.7, 0.8), (0.9, 0.2))],
            }
            word = "netview"
            segments = []
            x = 0.0
            advance = 1.0
            for ch in word:
                segs = letters.get(ch, [])
                for (x1, y1), (x2, y2) in segs:
                    segments.append(((x + x1, y1), (x + x2, y2)))
                x += advance
            # Center horizontally and vertically in unit box.
            total_w = max(1.0, x)
            out = []
            for (x1, y1), (x2, y2) in segments:
                nx1 = (x1 / total_w) - 0.5
                ny1 = y1 - 0.5
                nx2 = (x2 / total_w) - 0.5
                ny2 = y2 - 0.5
                out.append(((nx1, ny1), (nx2, ny2)))
            return out

        text_strokes = strokes_for_text()
        for face in faces:
            a, b, c, d = face
            pa = rotated[a]
            pb = rotated[b]
            pc = rotated[c]
            ab = (pb[0] - pa[0], pb[1] - pa[1], pb[2] - pa[2])
            ac = (pc[0] - pa[0], pc[1] - pa[1], pc[2] - pa[2])
            normal = (
                ab[1] * ac[2] - ab[2] * ac[1],
                ab[2] * ac[0] - ab[0] * ac[2],
                ab[0] * ac[1] - ab[1] * ac[0],
            )
            center = (
                (rotated[a][0] + rotated[b][0] + rotated[c][0] + rotated[d][0]) / 4.0,
                (rotated[a][1] + rotated[b][1] + rotated[c][1] + rotated[d][1]) / 4.0,
                (rotated[a][2] + rotated[b][2] + rotated[c][2] + rotated[d][2]) / 4.0,
            )
            view = (0.0 - center[0], 0.0 - center[1], 3.5 - center[2])
            dot = normal[0] * view[0] + normal[1] * view[1] + normal[2] * view[2]
            if dot <= 0:
                continue
            u2 = QtCore.QPointF(projected[b].x() - projected[a].x(),
                                projected[b].y() - projected[a].y())
            v2 = QtCore.QPointF(projected[d].x() - projected[a].x(),
                                projected[d].y() - projected[a].y())
            ulen = math.hypot(u2.x(), u2.y())
            vlen = math.hypot(v2.x(), v2.y())
            face_scale = 0.5 * min(ulen, vlen)
            if face_scale <= 0 or ulen == 0 or vlen == 0:
                continue
            udir = QtCore.QPointF(u2.x() / ulen, u2.y() / ulen)
            vdir = QtCore.QPointF(v2.x() / vlen, v2.y() / vlen)
            center2d = QtCore.QPointF(
                (projected[a].x() + projected[b].x() + projected[c].x() + projected[d].x()) * 0.25,
                (projected[a].y() + projected[b].y() + projected[c].y() + projected[d].y()) * 0.25,
            )
            for (x1, y1), (x2, y2) in text_strokes:
                p1 = QtCore.QPointF(
                    center2d.x() + (udir.x() * x1 + vdir.x() * y1) * face_scale,
                    center2d.y() + (udir.y() * x1 + vdir.y() * y1) * face_scale,
                )
                p2 = QtCore.QPointF(
                    center2d.x() + (udir.x() * x2 + vdir.x() * y2) * face_scale,
                    center2d.y() + (udir.y() * x2 + vdir.y() * y2) * face_scale,
                )
                buf_painter.drawLine(p1, p2)
        buf_painter.end()
        painter.drawImage(0, 0, self._buffer)


class AboutBackdropWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cube = WireCubeWidget(self)
        self.cube.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, True)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._layout = layout

    def set_content(self, widget):
        self._layout.addWidget(widget)
        self.cube.lower()
        widget.raise_()

    def resizeEvent(self, event):
        self.cube.setGeometry(self.rect())
        return super().resizeEvent(event)

    def mousePressEvent(self, event):
        self.cube.mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.cube.mouseReleaseEvent(event)


class ScanWorker(QtCore.QObject):
    upsert = QtCore.Signal(str, str, str, str)
    merge_identity = QtCore.Signal(str, str, str)
    update_ports = QtCore.Signal(str, list)
    update_name = QtCore.Signal(str, str)
    status = QtCore.Signal(str)
    finished = QtCore.Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._work_q = None
        self._queued = set()

    def start(self):
        t = threading.Thread(target=self.scan, daemon=True)
        t.start()

    def scan(self):
        self.status.emit("Scanning...")
        self._work_q = queue.Queue()
        self._queued = set()
        threading.Thread(target=self.background_worker, daemon=True).start()

        local_ip = get_local_ip()
        if not local_ip:
            self.status.emit("No network")
            self.finished.emit(0)
            return

        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        hosts = iter_subnet_hosts(local_ip, prefix=24)
        targets = [ip for ip in hosts if ip != local_ip and should_include_ip(ip, net)]
        found = set()
        def enqueue_work(ip, want_name=True, want_ports=True):
            if ip in self._queued:
                return
            self._queued.add(ip)
            self._work_q.put((ip, want_name, want_ports))

        # Add local machine immediately and enqueue checks
        local_name = socket.gethostname()
        self.upsert.emit(local_ip, local_name, "", "Pending")
        found.add(local_ip)
        enqueue_work(local_ip, want_name=False, want_ports=True)

        gateway = get_default_gateway()
        if gateway and gateway != local_ip and should_include_ip(gateway, net):
            if gateway not in found:
                self.upsert.emit(gateway, "", "", "Pending")
                found.add(gateway)
            enqueue_work(gateway, want_name=True, want_ports=True)

        arp = parse_arp_table()
        for ip, entry in arp.items():
            if ip == local_ip or not should_include_ip(ip, net):
                continue
            found.add(ip)
            name = entry.get("name", "")
            mac = entry.get("mac", "")
            self.upsert.emit(ip, name, mac, "Pending")
            enqueue_work(ip, want_name=not bool(name), want_ports=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as pinger:
            ping_futures = {pinger.submit(ping_host, ip, 10): ip for ip in targets}
            for fut in concurrent.futures.as_completed(ping_futures):
                ip = ping_futures[fut]
                try:
                    alive = fut.result()
                except Exception:
                    alive = False
                if not alive:
                    continue
                if ip in found or not should_include_ip(ip, net):
                    continue
                found.add(ip)
                self.upsert.emit(ip, "", "", "Pending")
                enqueue_work(ip, want_name=True, want_ports=True)

        arp = parse_arp_table()
        for ip, entry in arp.items():
            if ip in found or not should_include_ip(ip, net):
                continue
            found.add(ip)
            name = entry.get("name", "")
            mac = entry.get("mac", "")
            self.upsert.emit(ip, name, mac, "Pending")
            enqueue_work(ip, want_name=not bool(name), want_ports=True)

        arp = parse_arp_table()
        for ip, entry in arp.items():
            if ip not in found or not should_include_ip(ip, net):
                continue
            name = entry.get("name", "")
            mac = entry.get("mac", "")
            if name or mac:
                self.merge_identity.emit(ip, name, mac)

        self._work_q.put(None)
        self.finished.emit(len(found))

    def background_worker(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as name_pool, \
            concurrent.futures.ThreadPoolExecutor(max_workers=32) as port_pool:
            while True:
                item = self._work_q.get()
                if item is None:
                    break
                ip, want_name, want_ports = item
                if want_name:
                    fut = name_pool.submit(resolve_name, ip)
                    fut.add_done_callback(lambda f, ip=ip: self.update_name.emit(ip, safe_result(f, default="")))
                if want_ports:
                    fut = port_pool.submit(scan_ports, ip, [22, 80, 443])
                    fut.add_done_callback(lambda f, ip=ip: self.update_ports.emit(ip, safe_result(f, default=[])))


class NetViewQt(QtWidgets.QMainWindow):
    status_row_update = QtCore.Signal(int, bool, str, str, str)
    status_summary = QtCore.Signal(str)
    status_retry_enable = QtCore.Signal(bool)
    status_timeout_enable = QtCore.Signal(bool)
    status_retries_enable = QtCore.Signal(bool)
    status_refresh_enable = QtCore.Signal(bool)
    tasmota_row_update = QtCore.Signal(str, object)
    prereq_row_update = QtCore.Signal(int, bool, str, str)

    def __init__(self):
        super().__init__()
        self._config = load_config()
        self.setWindowTitle(f"netview {NETVIEW_VERSION}")
        self.resize(1300, 820)

        self._oui_db = load_oui_db()
        self._rows = {}
        self._scan_count = 0
        self._scan_running = False
        self._local_ip = None
        self._default_gateway = None
        self._name_raw_role = QtCore.Qt.UserRole + 1

        menu = self.menuBar().addMenu("Netview")
        quit_action = QtGui.QAction("Quit", self)
        quit_action.setShortcut(QtGui.QKeySequence.Quit)
        quit_action.triggered.connect(QtWidgets.QApplication.quit)
        menu.addAction(quit_action)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(10)

        bar = QtWidgets.QHBoxLayout()
        bar.setSpacing(12)
        bar.addStretch(1)
        layout.addLayout(bar)

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)
        self._tab_index_status = None
        self._tab_index_devices = None
        self._tab_index_known = None
        self._tab_index_about = None
        self._tab_index_tasmota = None
        self._tab_index_prereq = None

        self.model = QtGui.QStandardItemModel(0, 7, self)
        self.model.setHorizontalHeaderLabels(
            ["IP Address", "Web", "Known", "Name", "MAC", "MAC Vendor", "Ports"]
        )

        self.proxy = SortProxy(self)
        self.proxy.setSourceModel(self.model)

        self.view = QtWidgets.QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.view.verticalHeader().setVisible(False)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.view.setEditTriggers(
            QtWidgets.QAbstractItemView.DoubleClicked
            | QtWidgets.QAbstractItemView.EditKeyPressed
            | QtWidgets.QAbstractItemView.SelectedClicked
        )
        self.view.setShowGrid(False)
        self.view.setAlternatingRowColors(True)
        self.view.setWordWrap(False)
        self.view.setCornerButtonEnabled(False)
        self.view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self.show_table_context_menu)
        self.view.clicked.connect(self.on_device_clicked)

        status_tab = QtWidgets.QWidget()
        status_layout = QtWidgets.QVBoxLayout(status_tab)
        status_layout.setContentsMargins(8, 8, 8, 8)
        status_layout.setSpacing(10)

        status_bar = QtWidgets.QHBoxLayout()
        self.status_retry = QtWidgets.QPushButton("Refresh")
        self.status_retry.clicked.connect(self.start_status_checks)
        self.status_timeout = QtWidgets.QComboBox()
        self.status_timeout.addItems(["5", "10", "20", "50", "100", "200", "500", "1000", "2000", "5000", "10000"])
        self.status_timeout.setCurrentText("200")
        self.status_timeout.currentIndexChanged.connect(self.on_timeout_changed)
        self.status_retries = QtWidgets.QComboBox()
        self.status_retries.addItems(["1", "2", "3", "5", "10"])
        self.status_retries.setCurrentText("5")
        self.status_retries.currentIndexChanged.connect(self.on_retries_changed)
        self.status_refresh = QtWidgets.QComboBox()
        self.status_refresh.addItems(["Off", "2s", "5s", "10s", "15s", "20s", "30s", "60s", "2m", "5m", "10m", "30m", "1h"])
        self.status_refresh.setCurrentText("Off")
        self.status_refresh.currentIndexChanged.connect(self.on_refresh_changed)
        self.status_text = QtWidgets.QLabel("Idle")
        self.status_search_box = QtWidgets.QLineEdit()
        self.status_search_box.setPlaceholderText("Filter...")
        self.status_search_box.setClearButtonEnabled(True)
        self.status_search_box.textChanged.connect(self.on_status_search_changed)
        status_bar.addWidget(self.status_retry)
        status_bar.addWidget(QtWidgets.QLabel("Ping timeout (ms):"))
        status_bar.addWidget(self.status_timeout)
        status_bar.addWidget(QtWidgets.QLabel("Retries:"))
        status_bar.addWidget(self.status_retries)
        status_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        status_bar.addWidget(self.status_refresh)
        status_bar.addWidget(self.status_text)
        status_bar.addStretch(1)
        status_bar.addWidget(self.status_search_box)
        status_layout.addLayout(status_bar)

        self.status_model = QtGui.QStandardItemModel(0, 5, self)
        self.status_model.setHorizontalHeaderLabels(["Status", "Test", "IP", "Ping", "Details"])
        self.status_proxy = SortProxy(self)
        self.status_proxy.setSourceModel(self.status_model)

        self.status_view = QtWidgets.QTableView()
        self.status_view.setModel(self.status_proxy)
        self.status_view.setSortingEnabled(True)
        self.status_view.horizontalHeader().setStretchLastSection(True)
        self.status_view.verticalHeader().setVisible(False)
        self.status_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.status_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.status_view.setShowGrid(False)
        self.status_view.setAlternatingRowColors(True)
        self.status_view.setWordWrap(False)
        status_header = self.status_view.horizontalHeader()
        for col in range(4):
            status_header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        status_header.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        self.status_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.status_view.customContextMenuRequested.connect(self.show_table_context_menu)
        status_layout.addWidget(self.status_view)
        self._tab_index_status = self.tabs.addTab(status_tab, "Network Status")

        tasmota_tab = QtWidgets.QWidget()
        tasmota_layout = QtWidgets.QVBoxLayout(tasmota_tab)
        tasmota_layout.setContentsMargins(8, 8, 8, 8)
        tasmota_layout.setSpacing(10)

        tasmota_bar = QtWidgets.QHBoxLayout()
        self.tasmota_rescan = QtWidgets.QPushButton("Rescan")
        self.tasmota_rescan.clicked.connect(self.start_tasmota_scan)
        self.tasmota_refresh = QtWidgets.QPushButton("Refresh")
        self.tasmota_refresh.clicked.connect(self.refresh_tasmota)
        self.tasmota_refresh_box = QtWidgets.QComboBox()
        self.tasmota_refresh_box.addItems(["Off", "2s", "5s", "10s", "15s", "20s", "30s", "60s", "2m", "5m", "10m", "30m", "1h"])
        self.tasmota_refresh_box.setCurrentText("Off")
        self.tasmota_refresh_box.currentIndexChanged.connect(self.on_tasmota_refresh_changed)
        self.tasmota_search_box = QtWidgets.QLineEdit()
        self.tasmota_search_box.setPlaceholderText("Filter...")
        self.tasmota_search_box.setClearButtonEnabled(True)
        self.tasmota_search_box.textChanged.connect(self.on_tasmota_search_changed)
        tasmota_bar.addWidget(self.tasmota_rescan)
        tasmota_bar.addWidget(self.tasmota_refresh)
        tasmota_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        tasmota_bar.addWidget(self.tasmota_refresh_box)
        tasmota_bar.addStretch(1)
        tasmota_bar.addWidget(self.tasmota_search_box)
        tasmota_layout.addLayout(tasmota_bar)

        self.tasmota_model = QtGui.QStandardItemModel(0, 11, self)
        self.tasmota_model.setHorizontalHeaderLabels(
            ["Name", "State", "Switch", "Web", "IP", "Power", "Today", "Yesterday", "Total", "WiFi", "Details"]
        )
        self.tasmota_proxy = SortProxy(self)
        self.tasmota_proxy.setSourceModel(self.tasmota_model)
        self.tasmota_view = QtWidgets.QTableView()
        self.tasmota_view.setModel(self.tasmota_proxy)
        self.tasmota_view.setSortingEnabled(True)
        t_header = self.tasmota_view.horizontalHeader()
        t_header.setStretchLastSection(False)
        for col in range(0, 10):
            t_header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        t_header.setSectionResizeMode(10, QtWidgets.QHeaderView.Stretch)
        self.tasmota_view.verticalHeader().setVisible(False)
        self.tasmota_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tasmota_view.setEditTriggers(QtWidgets.QAbstractItemView.AllEditTriggers)
        self.tasmota_view.setShowGrid(False)
        self.tasmota_view.setAlternatingRowColors(True)
        self.tasmota_view.setWordWrap(False)
        self.tasmota_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tasmota_view.customContextMenuRequested.connect(self.show_table_context_menu)
        self.tasmota_view.clicked.connect(self.on_tasmota_clicked)
        tasmota_layout.addWidget(self.tasmota_view)
        devices_tab = QtWidgets.QWidget()
        devices_layout = QtWidgets.QVBoxLayout(devices_tab)
        devices_layout.setContentsMargins(8, 8, 8, 8)
        devices_layout.setSpacing(10)

        devices_bar = QtWidgets.QHBoxLayout()
        devices_bar.setSpacing(12)
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.start_scan)
        self.status = QtWidgets.QLineEdit("Idle")
        self.status.setReadOnly(True)
        self.status.setMinimumWidth(220)
        self.show_domain_box = QtWidgets.QCheckBox("Show domain")
        self.show_domain_box.setChecked(False)
        self.show_domain_box.stateChanged.connect(self.on_show_domain_changed)
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Filter devices...")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self.on_device_search_changed)
        self.devices_refresh_box = QtWidgets.QComboBox()
        self.devices_refresh_box.addItems(["Off", "10s", "15s", "20s", "30s", "60s", "2m", "5m", "10m", "30m", "1h"])
        self.devices_refresh_box.setCurrentText("Off")
        self.devices_refresh_box.currentIndexChanged.connect(self.on_devices_refresh_changed)
        devices_bar.addWidget(self.refresh_btn)
        devices_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        devices_bar.addWidget(self.devices_refresh_box)
        devices_bar.addWidget(self.show_domain_box)
        devices_bar.addWidget(self.status)
        devices_bar.addStretch(1)
        devices_bar.addWidget(self.search_box)
        devices_layout.addLayout(devices_bar)

        devices_layout.addWidget(self.view)

        self._tab_index_devices = self.tabs.addTab(devices_tab, "Local Devices")

        known_tab = QtWidgets.QWidget()
        known_layout = QtWidgets.QVBoxLayout(known_tab)
        known_layout.setContentsMargins(8, 8, 8, 8)
        known_layout.setSpacing(10)

        known_bar = QtWidgets.QHBoxLayout()
        known_bar.addStretch(1)
        self.known_search_box = QtWidgets.QLineEdit()
        self.known_search_box.setPlaceholderText("Filter...")
        self.known_search_box.setClearButtonEnabled(True)
        self.known_search_box.textChanged.connect(self.on_known_search_changed)
        known_bar.addWidget(self.known_search_box)
        known_layout.addLayout(known_bar)

        self.known_model = QtGui.QStandardItemModel(0, 6, self)
        self.known_model.setHorizontalHeaderLabels(
            ["Del", "IP", "User Name", "DNS", "MAC", "Vendor"]
        )
        self.known_proxy = SortProxy(self)
        self.known_proxy.setSourceModel(self.known_model)
        self.known_view = QtWidgets.QTableView()
        self.known_view.setModel(self.known_proxy)
        self.known_view.setSortingEnabled(True)
        self.known_view.horizontalHeader().setStretchLastSection(True)
        self.known_view.verticalHeader().setVisible(False)
        self.known_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.known_view.setEditTriggers(
            QtWidgets.QAbstractItemView.DoubleClicked
            | QtWidgets.QAbstractItemView.EditKeyPressed
            | QtWidgets.QAbstractItemView.SelectedClicked
        )
        self.known_view.setShowGrid(False)
        self.known_view.setAlternatingRowColors(True)
        self.known_view.setWordWrap(False)
        self.known_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.known_view.customContextMenuRequested.connect(self.show_table_context_menu)
        self.known_view.clicked.connect(self.on_known_devices_clicked)
        known_layout.addWidget(self.known_view)
        self._tab_index_known = self.tabs.addTab(known_tab, "Known Devices")
        self._tab_index_tasmota = self.tabs.addTab(tasmota_tab, "Tasmota Switches")

        prereq_tab = QtWidgets.QWidget()
        prereq_layout = QtWidgets.QVBoxLayout(prereq_tab)
        prereq_layout.setContentsMargins(8, 8, 8, 8)
        prereq_layout.setSpacing(10)

        self.prereq_model = QtGui.QStandardItemModel(0, 3, self)
        self.prereq_model.setHorizontalHeaderLabels(["Status", "Tool", "Path"])
        self.prereq_proxy = SortProxy(self)
        self.prereq_proxy.setSourceModel(self.prereq_model)
        prereq_bar = QtWidgets.QHBoxLayout()
        prereq_bar.addStretch(1)
        self.prereq_search_box = QtWidgets.QLineEdit()
        self.prereq_search_box.setPlaceholderText("Filter...")
        self.prereq_search_box.setClearButtonEnabled(True)
        self.prereq_search_box.textChanged.connect(self.on_prereq_search_changed)
        prereq_bar.addWidget(self.prereq_search_box)
        prereq_layout.addLayout(prereq_bar)
        self.prereq_view = QtWidgets.QTableView()
        self.prereq_view.setModel(self.prereq_proxy)
        self.prereq_view.setSortingEnabled(True)
        self.prereq_view.horizontalHeader().setStretchLastSection(True)
        self.prereq_view.verticalHeader().setVisible(False)
        self.prereq_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.prereq_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.prereq_view.setShowGrid(False)
        self.prereq_view.setAlternatingRowColors(True)
        self.prereq_view.setWordWrap(False)
        prereq_header = self.prereq_view.horizontalHeader()
        prereq_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        prereq_header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        prereq_header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        prereq_layout.addWidget(self.prereq_view)
        self._tab_index_prereq = self.tabs.addTab(prereq_tab, "Prerequisites")

        about_tab = QtWidgets.QWidget()
        about_layout = QtWidgets.QVBoxLayout(about_tab)
        about_layout.setContentsMargins(8, 8, 8, 8)
        about_layout.setSpacing(10)
        self.about_tabs = QtWidgets.QTabWidget()
        about_layout.addWidget(self.about_tabs)

        about_info_tab = QtWidgets.QWidget()
        about_info_layout = QtWidgets.QVBoxLayout(about_info_tab)
        about_info_layout.setContentsMargins(8, 8, 8, 8)
        about_info_layout.setSpacing(10)
        py_version = sys.version.split()[0]
        pyside_version = getattr(PySide6, "__version__", "unknown")
        netview_version = NETVIEW_VERSION
        about_text = (
            f"netview version {NETVIEW_VERSION}<br>"
            "Copyright (c) 2026 Johannes Overmann<br>"
            "<a href=\"https://github.com/jovermann/netview\">https://github.com/jovermann/netview</a><br><br><br>"
            f"Python: {py_version}<br>"
            f"PySide: {pyside_version}<br>"
        )
        about_container = AboutBackdropWidget()
        self.about_cube = about_container.cube
        self.about_info = QtWidgets.QLabel()
        self.about_info.setTextFormat(QtCore.Qt.RichText)
        self.about_info.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.about_info.setOpenExternalLinks(True)
        self.about_info.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, True)
        self.about_info.setText(about_text)
        self.about_info.setWordWrap(True)
        self.about_info.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.about_info.setMargin(8)
        self.about_info.setAutoFillBackground(False)
        self.about_info.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        about_container.set_content(self.about_info)
        about_info_layout.addWidget(about_container)
        self.about_tabs.addTab(about_info_tab, "About netview")

        license_tab = QtWidgets.QWidget()
        license_layout = QtWidgets.QVBoxLayout(license_tab)
        license_layout.setContentsMargins(8, 8, 8, 8)
        license_layout.setSpacing(10)
        license_bar = QtWidgets.QHBoxLayout()
        self.license_show_disclaimer = QtWidgets.QPushButton("Show Confirmation Dialog")
        self.license_show_disclaimer.clicked.connect(self.on_show_disclaimer_clicked)
        license_bar.addWidget(self.license_show_disclaimer)
        license_bar.addStretch(1)
        license_layout.addLayout(license_bar)
        self.license_text = QtWidgets.QPlainTextEdit()
        self.license_text.setReadOnly(True)
        try:
            license_body = (Path(__file__).parent / "LICENSE").read_text()
        except Exception:
            license_body = "LICENSE file not found."
        license_text = (
            f"{license_body}\n\n"
            "By using this software you confirm:\n"
            f"{disclaimer_bullets_text()}\n"
        )
        self.license_text.setPlainText(license_text)
        license_layout.addWidget(self.license_text)
        self.about_tabs.addTab(license_tab, "License and Disclaimer")
        license_palette = self.license_text.palette()
        bg = license_palette.color(QtGui.QPalette.Base).name()
        fg = license_palette.color(QtGui.QPalette.Text).name()
        self.about_cube.set_colors(bg, fg)
        self.about_info.setStyleSheet(f"background-color: rgba(0, 0, 0, 0); color: {fg};")

        self._tab_index_about = self.tabs.addTab(about_tab, "About")

        base_font = QtGui.QFont()
        base_font.setPointSize(13)
        self.setFont(base_font)
        self.status.setFont(base_font)
        self.view.setFont(base_font)
        self.status_view.setFont(base_font)
        self.tasmota_view.setFont(base_font)
        self.prereq_view.setFont(base_font)
        self.known_view.setFont(base_font)
        self.license_text.setFont(base_font)
        self.about_info.setFont(base_font)
        self.mono_font = QtGui.QFont("Menlo", 12)
        self.view.verticalHeader().setDefaultSectionSize(28)
        self.ensure_device_column_widths()
        self.tasmota_view.verticalHeader().setDefaultSectionSize(28)
        self.prereq_view.verticalHeader().setDefaultSectionSize(28)
        self.view.horizontalHeader().sortIndicatorChanged.connect(self.on_table_sort_changed)
        self.status_view.horizontalHeader().sortIndicatorChanged.connect(self.on_table_sort_changed)
        self.tasmota_view.horizontalHeader().sortIndicatorChanged.connect(self.on_table_sort_changed)
        self.prereq_view.horizontalHeader().sortIndicatorChanged.connect(self.on_table_sort_changed)
        self.known_view.horizontalHeader().sortIndicatorChanged.connect(self.on_table_sort_changed)

        self.worker = ScanWorker()
        self.worker.upsert.connect(self.upsert_row)
        self.worker.merge_identity.connect(self.merge_identity)
        self.worker.update_ports.connect(self.update_ports)
        self.worker.update_name.connect(self.apply_name)
        self.worker.status.connect(self.status.setText)
        self.worker.finished.connect(self.scan_finished)
        self.status_row_update.connect(self.update_status_row)
        self.status_summary.connect(self.status_text.setText)
        self.status_retry_enable.connect(self.status_retry.setEnabled)
        self.status_timeout_enable.connect(self.status_timeout.setEnabled)
        self.status_retries_enable.connect(self.status_retries.setEnabled)
        self.status_refresh_enable.connect(self.status_refresh.setEnabled)
        self.status_timer = QtCore.QTimer(self)
        self.status_timer.timeout.connect(self.on_status_timer)
        self._status_running = False
        self._tasmota_rows = {}
        self._tasmota_scanning = False
        self._tasmota_updating = False
        self.tasmota_row_update.connect(self.update_tasmota_row)
        self.tasmota_model.itemChanged.connect(self.on_tasmota_item_changed)
        self.prereq_row_update.connect(self.update_prereq_row)
        self.tasmota_timer = QtCore.QTimer(self)
        self.tasmota_timer.timeout.connect(self.on_tasmota_timer)
        self.devices_timer = QtCore.QTimer(self)
        self.devices_timer.timeout.connect(self.on_devices_timer)
        self._prereq_rows = []
        self._known_store_macs, self._known_store_names = extract_known_hosts(self._config)
        vprint(f"[netview] known: loaded macs={len(self._known_store_macs)} names={len(self._known_store_names)}")
        self._known_updating = False
        self._name_updating = False
        self._known_programmatic = 0
        self._name_programmatic = 0
        self._known_devices_updating = False
        ui_cfg = self._config.get("ui", {})
        self._disclaimer_state = "accepted" if ui_cfg.get("disclaimer_ok") == "On" else "pending"
        self._disclaimer_shown = False
        self.model.itemChanged.connect(self.on_known_item_changed)
        self.model.itemChanged.connect(self.on_name_item_changed)
        self.known_model.itemChanged.connect(self.on_known_devices_item_changed)
        self._config_timer = QtCore.QTimer(self)
        self._config_timer.setSingleShot(True)
        self._config_timer.timeout.connect(self.flush_config)

        # Allow quitting with Ctrl+C even when the app has focus.
        QtWidgets.QApplication.instance().installEventFilter(self)

        self._startup_scan_scheduled = False
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self._status_initialized = False
        QtCore.QTimer.singleShot(200, self.raise_)
        QtCore.QTimer.singleShot(250, self.activateWindow)
        self.apply_saved_ui()
        QtCore.QTimer.singleShot(300, self.startup_tasks_with_disclaimer)
        self.refresh_known_devices_table()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_C and (event.modifiers() & QtCore.Qt.ControlModifier):
                QtWidgets.QApplication.quit()
                return True
        return super().eventFilter(obj, event)

    def start_scan(self):
        if not self.ensure_disclaimer():
            return
        if self._scan_running:
            return
        self._scan_running = True
        self.refresh_btn.setEnabled(False)
        self.status.setText("Scanning...")
        self.clear_table()
        self._scan_count = 0
        self._local_ip = get_local_ip()
        self._default_gateway = get_default_gateway()
        self.worker.start()

    def clear_table(self):
        self.model.removeRows(0, self.model.rowCount())
        self._rows = {}

    def upsert_row(self, ip, name, mac, ports):
        row = self._rows.get(ip)
        fm = format_mac(mac)
        vendor = vendor_for_mac(fm, self._oui_db)
        values = [ip, "", "", "", fm, vendor, ports]
        if row is None:
            row = self.model.rowCount()
            self.model.insertRow(row)
            self._rows[ip] = row
            self._scan_count += 1
            self.status.setText(f"Scanning... ({self._scan_count} devices)")
            self.update_tab_counts()

        self._known_updating = True
        for col, val in enumerate(values):
            if col == 3:
                continue
            item = self.model.item(row, col)
            if item is None:
                item = QtGui.QStandardItem(str(val))
                if col == 4:
                    item.setFont(self.mono_font)
                if col == 5 and str(val).startswith("(") and str(val).endswith(")"):
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
                item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
                self.model.setItem(row, col, item)
            else:
                item.setText(str(val))
                if col == 5 and str(val).startswith("(") and str(val).endswith(")"):
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
                item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
        self.set_name_item(row, ip, name)
        self.update_web_column(row)
        self.update_known_column(row, mac)
        self._known_updating = False
        header = self.view.horizontalHeader()
        self.view.sortByColumn(header.sortIndicatorSection(), header.sortIndicatorOrder())
        self.view.resizeColumnsToContents()
        self.ensure_device_column_widths()
        # Auto-size status table columns to contents.

    def update_ports(self, ip, ports):
        row = self._rows.get(ip)
        if row is None:
            return
        ports_text = ",".join(str(p) for p in ports) if ports else ""
        item = self.model.item(row, 6)
        if item is None:
            item = QtGui.QStandardItem(ports_text)
            self.model.setItem(row, 6, item)
        else:
            item.setText(ports_text)
        self.update_web_column(row)

    def merge_identity(self, ip, name, mac):
        row = self._rows.get(ip)
        if row is None:
            return
        if name:
            item = self.model.item(row, 3)
            raw = item.data(self._name_raw_role) if item else ""
            if not raw:
                self.set_name_item(row, ip, name)
        fm = format_mac(mac)
        if fm:
            item = self.model.item(row, 4)
            if item is None or not item.text():
                mac_item = QtGui.QStandardItem(fm)
                mac_item.setFont(self.mono_font)
                self.model.setItem(row, 4, mac_item)
            vendor = vendor_for_mac(fm, self._oui_db)
            if vendor:
                v_item = self.model.item(row, 5)
                if v_item is None or not v_item.text():
                    v_item = QtGui.QStandardItem(vendor)
                    if vendor.startswith("(") and vendor.endswith(")"):
                        v_item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
                    self.model.setItem(row, 5, v_item)
        self.update_web_column(row)
        self.update_known_column(row, mac)
        self.set_name_item(row, ip)

    def apply_name(self, ip, name):
        if not name:
            return
        row = self._rows.get(ip)
        if row is None:
            return
        item = self.model.item(row, 3)
        raw = item.data(self._name_raw_role) if item else ""
        if not raw:
            self.set_name_item(row, ip, name)
        self.update_web_column(row)

    def scan_finished(self, count):
        self._scan_running = False
        self.refresh_btn.setEnabled(True)
        self.status.setText(f"Done ({count} devices)")
        self.update_tab_counts()

    def on_tab_changed(self, index):
        if index != self._tab_index_devices:
            self.devices_timer.stop()
        if index == self._tab_index_status:
            self.start_status_checks()
            self.apply_auto_refresh()
        elif index == self._tab_index_devices:
            self.status_timer.stop()
            self.start_scan()
            self.apply_devices_auto_refresh()
        elif index == self._tab_index_tasmota:
            self.status_timer.stop()
            if not self._tasmota_rows:
                self.start_tasmota_scan()
            self.apply_tasmota_auto_refresh()
        elif index == self._tab_index_prereq:
            self.start_prereq_checks()
        self.schedule_config_write()

    def schedule_initial_scan(self):
        if self._startup_scan_scheduled:
            return
        self._startup_scan_scheduled = True
        if self._tab_index_devices is None:
            return
        current = self.tabs.currentIndex()
        if current == self._tab_index_devices:
            self.start_scan()
            return
        self.start_scan()

    def startup_tasks(self):
        self.start_status_checks()
        self.start_tasmota_scan()
        self.start_prereq_checks()
        self.schedule_initial_scan()

    def ensure_disclaimer(self):
        return self._disclaimer_state == "accepted"

    def startup_tasks_with_disclaimer(self):
        if self._disclaimer_state == "accepted":
            self.startup_tasks()
            return
        if self._disclaimer_state == "declined" or self._disclaimer_shown:
            return
        self._disclaimer_shown = True
        dlg = QtWidgets.QMessageBox(self)
        dlg.setWindowTitle("Netview Disclaimer")
        dlg.setIcon(QtWidgets.QMessageBox.Warning)
        dlg.setText(
            "Disclaimer\n\n"
            "By proceeding, you confirm:\n"
            f"{disclaimer_bullets_text()}\n\n"
            "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
            "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
            "FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT\n"
            "SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE\n"
            "FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,\n"
            "ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n"
            "DEALINGS IN THE SOFTWARE."
        )
        dlg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Close)
        dlg.button(QtWidgets.QMessageBox.Ok).setText("OK")
        dlg.button(QtWidgets.QMessageBox.Close).setText("Quit")
        checkbox = QtWidgets.QCheckBox("Do not ask this again")
        dlg.setCheckBox(checkbox)
        result = dlg.exec()
        if result == QtWidgets.QMessageBox.Ok:
            self._disclaimer_state = "accepted"
            if checkbox.isChecked():
                ui = self._config.get("ui", {})
                ui["disclaimer_ok"] = "On"
                self._config["ui"] = ui
                write_config(self._config)
            self.startup_tasks()
            return
        self._disclaimer_state = "declined"
        QtWidgets.QApplication.quit()

    def start_status_checks(self):
        if not self.ensure_disclaimer():
            return
        vprint("[netview] status: start")
        if self._status_running:
            return
        self._status_running = True
        self.status_retry.setEnabled(False)
        self.status_timeout_enable.emit(False)
        self.status_retries_enable.emit(False)
        self.status_text.setText("Checking network...")
        self.status_model.removeRows(0, self.status_model.rowCount())
        dns_servers = get_dns_servers()
        self._status_dns = dns_servers
        self._iface_info = get_interface_info()
        tips = status_tooltips()
        self._status_row_tooltip = {}
        self._status_rows = {
            "Interface status": self.add_status_row_pending("Interface status", self._iface_info.get("ip", ""), tooltip=tips.get("Interface status", "")),
            "DHCP lease": self.add_status_row_pending("DHCP lease", self._iface_info.get("ip", ""), tooltip=tips.get("DHCP lease", "")),
            "Local gateway": self.add_status_row_pending("Local gateway", "", tooltip=tips.get("Local gateway", "")),
            "Gateway ARP": self.add_status_row_pending("Gateway ARP", "", tooltip=tips.get("Gateway ARP", "")),
            "Default route": self.add_status_row_pending("Default route", "", tooltip=tips.get("Default route", "")),
            "DNS system resolve": self.add_status_row_pending("DNS system resolve", "", tooltip=tips.get("DNS system resolve", "")),
            "DNS server 1": self.add_status_row_pending("DNS server 1", "", tooltip=tips.get("DNS server 1", "")) if len(dns_servers) >= 1 else None,
            "DNS server 2": self.add_status_row_pending("DNS server 2", "", tooltip=tips.get("DNS server 2", "")) if len(dns_servers) >= 2 else None,
            "Reverse lookup 1.1.1.1": self.add_status_row_pending("Reverse lookup 1.1.1.1", "1.1.1.1", tooltip=tips.get("Reverse lookup 1.1.1.1", "")),
            "Reverse lookup 8.8.8.8": self.add_status_row_pending("Reverse lookup 8.8.8.8", "8.8.8.8", tooltip=tips.get("Reverse lookup 8.8.8.8", "")),
            "Ping 8.8.8.8": self.add_status_row_pending("Ping 8.8.8.8", "8.8.8.8", tooltip=tips.get("Ping 8.8.8.8", "")),
            "Ping 1.1.1.1": self.add_status_row_pending("Ping 1.1.1.1", "1.1.1.1", tooltip=tips.get("Ping 1.1.1.1", "")),
            "Ping heise.de": self.add_status_row_pending("Ping heise.de", "", tooltip=tips.get("Ping heise.de", "")),
            "TCP 443 heise.de": self.add_status_row_pending("TCP 443 heise.de", "", tooltip=tips.get("TCP 443 heise.de", "")),
            "HTTP 204 check": self.add_status_row_pending("HTTP 204 check", "", tooltip=tips.get("HTTP 204 check", "")),
            "Apple captive check": self.add_status_row_pending("Apple captive check", "", tooltip=tips.get("Apple captive check", "")),
            "Traceroute 8.8.8.8": self.add_status_row_pending("Traceroute 8.8.8.8", "", tooltip=tips.get("Traceroute 8.8.8.8", "")),
            "DNS hijack check": self.add_status_row_pending("DNS hijack check", "", tooltip=tips.get("DNS hijack check", "")),
        }
        for key, row in self._status_rows.items():
            if row is not None:
                self._status_row_tooltip[row] = tips.get(key, "")
        thread = threading.Thread(target=self.run_status_checks, daemon=True)
        thread.start()
        self.update_tab_counts()

    def add_status_row_pending(self, test, ip="", details="", tooltip=""):
        row = self.status_model.rowCount()
        self.status_model.insertRow(row)
        item = QtGui.QStandardItem("\U0001F501")
        item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
        self.status_model.setItem(row, 0, item)
        self.status_model.setItem(row, 1, QtGui.QStandardItem(test))
        self.status_model.setItem(row, 2, QtGui.QStandardItem(ip))
        self.status_model.setItem(row, 3, QtGui.QStandardItem(""))
        self.status_model.setItem(row, 4, QtGui.QStandardItem(details))
        if tooltip:
            for col in range(5):
                it = self.status_model.item(row, col)
                if it is not None:
                    it.setToolTip(tooltip)
        return row

    def update_status_row(self, row, ok, details, ip="", ping=""):
        status_icon = "✅" if ok else "❌"
        item = QtGui.QStandardItem(status_icon)
        item.setForeground(QtGui.QBrush(QtGui.QColor("#1E8E3E" if ok else "#D93025")))
        self.status_model.setItem(row, 0, item)
        if ip:
            self.status_model.setItem(row, 2, QtGui.QStandardItem(ip))
        if ping:
            self.status_model.setItem(row, 3, QtGui.QStandardItem(ping))
        self.status_model.setItem(row, 4, QtGui.QStandardItem(details))
        tip = getattr(self, "_status_row_tooltip", {}).get(row, "")
        if tip:
            for col in range(5):
                it = self.status_model.item(row, col)
                if it is not None:
                    it.setToolTip(tip)

    def ensure_device_column_widths(self):
        # Keep Name and Vendor columns comfortably wide.
        name_w = max(self.view.columnWidth(3), 220)
        vendor_w = max(self.view.columnWidth(5), 240)
        self.view.setColumnWidth(3, name_w)
        self.view.setColumnWidth(5, vendor_w)
        self.view.setColumnWidth(1, 40)
        self.view.setColumnWidth(2, 30)

    def start_tasmota_scan(self):
        if not self.ensure_disclaimer():
            return
        if self._tasmota_scanning:
            return
        self._tasmota_scanning = True
        self.tasmota_model.removeRows(0, self.tasmota_model.rowCount())
        self._tasmota_rows = {}
        self.update_tab_counts()
        thread = threading.Thread(target=self.tasmota_scan_worker, daemon=True)
        thread.start()

    def tasmota_scan_worker(self):
        local_ip = get_local_ip()
        if not local_ip:
            self._tasmota_scanning = False
            return
        parts = local_ip.split(".")
        if len(parts) != 4:
            self._tasmota_scanning = False
            return
        base = ".".join(parts[:3])
        ips = [f"{base}.{i}" for i in range(1, 255)]

        def probe(ip):
            if not tcp_port_open(ip, 80, timeout=0.2):
                return None
            status = tasmota_fetch_status(ip, timeout=1.5)
            if not status:
                return None
            return ip, status

        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as exe:
            future_map = {exe.submit(probe, ip): ip for ip in ips}
            for fut in concurrent.futures.as_completed(future_map):
                res = safe_result(fut)
                if not res:
                    continue
                ip, status = res
                self.tasmota_row_update.emit(ip, status)

        self._tasmota_scanning = False

    def refresh_tasmota(self):
        if not self._tasmota_rows:
            return
        thread = threading.Thread(target=self.tasmota_refresh_worker, daemon=True)
        thread.start()

    def tasmota_refresh_worker(self):
        ips = list(self._tasmota_rows.keys())
        def probe(ip):
            status = tasmota_fetch_status(ip, timeout=1.5)
            if not status:
                return None
            return ip, status
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as exe:
            future_map = {exe.submit(probe, ip): ip for ip in ips}
            for fut in concurrent.futures.as_completed(future_map):
                res = safe_result(fut)
                if not res:
                    continue
                ip, status = res
                self.tasmota_row_update.emit(ip, status)

    def update_tasmota_row(self, ip, status):
        row = self._tasmota_rows.get(ip)
        name = status.get("name") or ip
        power_state = status.get("power_state", "")
        power_w = status.get("power_w", "")
        today = status.get("today", "")
        yesterday = status.get("yesterday", "")
        total = status.get("total", "")
        model = status.get("model", "")
        wifi = status.get("wifi", "")
        if row is None:
            row = self.tasmota_model.rowCount()
            self.tasmota_model.insertRow(row)
            self._tasmota_rows[ip] = row
            self.update_tab_counts()

        def set_item(col, text, align=None, color=None, check=None):
            item = self.tasmota_model.item(row, col)
            if item is None:
                item = QtGui.QStandardItem(str(text))
                self.tasmota_model.setItem(row, col, item)
            else:
                item.setText(str(text))
            if align:
                item.setTextAlignment(align)
            if color:
                item.setForeground(QtGui.QBrush(QtGui.QColor(color)))
            if check is not None:
                item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
                item.setCheckState(QtCore.Qt.Checked if check else QtCore.Qt.Unchecked)
            return item

        set_item(0, name)
        if power_state == "ON":
            set_item(1, "On", align=QtCore.Qt.AlignCenter, color="#1E8E3E")
        elif power_state == "OFF":
            set_item(1, "Off", align=QtCore.Qt.AlignCenter, color="#6E6E73")
        else:
            set_item(1, "", align=QtCore.Qt.AlignCenter)
        switch_item = self.tasmota_model.item(row, 2)
        if switch_item is None:
            switch_item = QtGui.QStandardItem("")
            self.tasmota_model.setItem(row, 2, switch_item)
        switch_item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsUserCheckable)
        switch_item.setCheckState(QtCore.Qt.Checked if power_state == "ON" else QtCore.Qt.Unchecked)
        web_item = self.tasmota_model.item(row, 3)
        if web_item is None:
            web_item = QtGui.QStandardItem("")
            self.tasmota_model.setItem(row, 3, web_item)
        web_item.setText("🌐")
        web_item.setData(f"http://{ip}", QtCore.Qt.UserRole)
        web_item.setTextAlignment(QtCore.Qt.AlignCenter)
        set_item(4, ip)
        power_text = f"{power_w} W" if power_w else ""
        today_text = f"{today} kWh" if today else ""
        yesterday_text = f"{yesterday} kWh" if yesterday else ""
        total_text = f"{total} kWh" if total else ""
        set_item(5, power_text, align=QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        set_item(6, today_text, align=QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        set_item(7, yesterday_text, align=QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        set_item(8, total_text, align=QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        set_item(9, wifi)
        set_item(10, model)
        self.tasmota_view.resizeColumnsToContents()
        self.tasmota_view.setColumnWidth(3, 30)
        header = self.tasmota_view.horizontalHeader()
        self.tasmota_view.sortByColumn(header.sortIndicatorSection(), header.sortIndicatorOrder())

    def on_tasmota_item_changed(self, item):
        if self._tasmota_updating:
            return
        if item.column() != 2:
            return
        ip_item = self.tasmota_model.item(item.row(), 4)
        if not ip_item:
            return
        ip = ip_item.text()
        desired = item.checkState() == QtCore.Qt.Checked

        def worker():
            result = tasmota_set_power(ip, desired, timeout=2.0)
            status = tasmota_fetch_status(ip, timeout=2.0)
            if status:
                self.tasmota_row_update.emit(ip, status)
            elif result:
                self.tasmota_row_update.emit(ip, {"name": "", "model": "", "wifi": "", "power_state": result, "power_w": "", "today": "", "yesterday": "", "total": ""})

        threading.Thread(target=worker, daemon=True).start()

    def on_tasmota_clicked(self, index):
        if not index.isValid():
            return
        model = self.tasmota_view.model()
        source_index = index
        source_model = model
        if source_index.column() != 3:
            return
        item = source_model.item(source_index.row(), source_index.column())
        url = item.data(QtCore.Qt.UserRole) if item else ""
        if url:
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))

    def on_tasmota_refresh_changed(self, _index):
        if self.tabs.currentIndex() == self._tab_index_tasmota:
            self.apply_tasmota_auto_refresh()
        self.schedule_config_write()

    def on_tasmota_timer(self):
        if self.tabs.currentIndex() == self._tab_index_tasmota:
            self.refresh_tasmota()

    def on_devices_timer(self):
        if self.tabs.currentIndex() == self._tab_index_devices:
            self.start_scan()

    def on_devices_refresh_changed(self, _index):
        if self.tabs.currentIndex() == self._tab_index_devices:
            self.apply_devices_auto_refresh()
        self.schedule_config_write()

    def apply_devices_auto_refresh(self):
        text = self.devices_refresh_box.currentText()
        if text == "Off":
            self.devices_timer.stop()
            return
        multipliers = {"s": 1, "m": 60, "h": 3600}
        try:
            if text[-1] in multipliers:
                interval = int(text[:-1]) * multipliers[text[-1]]
            else:
                interval = int(text)
        except Exception:
            self.devices_timer.stop()
            return
        self.devices_timer.start(interval * 1000)
        self.start_scan()
        self.schedule_config_write()

    def apply_tasmota_auto_refresh(self):
        text = self.tasmota_refresh_box.currentText()
        if text == "Off":
            self.tasmota_timer.stop()
            return
        multipliers = {"s": 1, "m": 60, "h": 3600}
        try:
            if text[-1] in multipliers:
                interval = int(text[:-1]) * multipliers[text[-1]]
            else:
                interval = int(text)
        except Exception:
            self.tasmota_timer.stop()
            return
        self.tasmota_timer.start(interval * 1000)
        self.refresh_tasmota()
        self.schedule_config_write()

    def schedule_config_write(self):
        self._config_timer.start(1000)

    def flush_config(self):
        ui = self._config.get("ui", {})
        ui["tab"] = base_tab_name(self.tabs.tabText(self.tabs.currentIndex()))
        ui["status_auto"] = self.status_refresh.currentText()
        ui["devices_auto"] = self.devices_refresh_box.currentText()
        ui["show_domain"] = "On" if self.show_domain_box.isChecked() else "Off"
        ui["tasmota_auto"] = self.tasmota_refresh_box.currentText()
        d_header = self.view.horizontalHeader()
        ui["devices_sort_col"] = str(d_header.sortIndicatorSection())
        ui["devices_sort_order"] = "desc" if d_header.sortIndicatorOrder() == QtCore.Qt.DescendingOrder else "asc"
        s_header = self.status_view.horizontalHeader()
        ui["status_sort_col"] = str(s_header.sortIndicatorSection())
        ui["status_sort_order"] = "desc" if s_header.sortIndicatorOrder() == QtCore.Qt.DescendingOrder else "asc"
        t_header = self.tasmota_view.horizontalHeader()
        ui["tasmota_sort_col"] = str(t_header.sortIndicatorSection())
        ui["tasmota_sort_order"] = "desc" if t_header.sortIndicatorOrder() == QtCore.Qt.DescendingOrder else "asc"
        p_header = self.prereq_view.horizontalHeader()
        ui["prereq_sort_col"] = str(p_header.sortIndicatorSection())
        ui["prereq_sort_order"] = "desc" if p_header.sortIndicatorOrder() == QtCore.Qt.DescendingOrder else "asc"
        k_header = self.known_view.horizontalHeader()
        ui["known_sort_col"] = str(k_header.sortIndicatorSection())
        ui["known_sort_order"] = "desc" if k_header.sortIndicatorOrder() == QtCore.Qt.DescendingOrder else "asc"
        ui["ping_timeout"] = self.status_timeout.currentText()
        ui["ping_retries"] = self.status_retries.currentText()
        self._config["ui"] = ui
        known_existing = self._config.get("known_hosts", {}) or {}
        known = {}
        for mac in sorted(self._known_store_macs):
            base = ["", "", "", ""]
            existing = known_existing.get(mac)
            if isinstance(existing, (list, tuple)):
                base = [str(v) for v in list(existing)[:4]]
                while len(base) < 4:
                    base.append("")
            user_name = self._known_store_names.get(mac, "")
            dns_name = base[1]
            ip_addr = base[2]
            vendor = base[3]
            row = None
            if mac:
                for ip, r in self._rows.items():
                    mac_item = self.model.item(r, 4)
                    if not mac_item:
                        continue
                    if format_mac(mac_item.text()).replace(":", "").upper() == mac:
                        row = r
                        break
            if row is not None:
                name_item = self.model.item(row, 3)
                raw_dns = name_item.data(self._name_raw_role) if name_item else ""
                ip_item = self.model.item(row, 0)
                vendor_item = self.model.item(row, 5)
                if raw_dns:
                    dns_name = str(raw_dns)
                if ip_item and ip_item.text():
                    ip_addr = ip_item.text()
                if vendor_item and vendor_item.text():
                    vendor = vendor_item.text()
            known[mac] = [user_name, dns_name, ip_addr, vendor]
        self._config["known_hosts"] = known
        write_config(self._config)

    def apply_saved_ui(self):
        ui = self._config.get("ui", {})
        if ui.get("status_auto"):
            self.status_refresh.setCurrentText(ui.get("status_auto"))
        if ui.get("devices_auto"):
            self.devices_refresh_box.setCurrentText(ui.get("devices_auto"))
        show_domain = ui.get("show_domain")
        if show_domain:
            self.show_domain_box.setChecked(show_domain == "On")
        if ui.get("tasmota_auto"):
            self.tasmota_refresh_box.setCurrentText(ui.get("tasmota_auto"))
        if ui.get("ping_timeout"):
            self.status_timeout.setCurrentText(ui.get("ping_timeout"))
        if ui.get("ping_retries"):
            self.status_retries.setCurrentText(ui.get("ping_retries"))
        self.apply_table_sort(self.view, ui.get("devices_sort_col"), ui.get("devices_sort_order"))
        self.apply_table_sort(self.status_view, ui.get("status_sort_col"), ui.get("status_sort_order"))
        self.apply_table_sort(self.tasmota_view, ui.get("tasmota_sort_col"), ui.get("tasmota_sort_order"))
        self.apply_table_sort(self.prereq_view, ui.get("prereq_sort_col"), ui.get("prereq_sort_order"))
        self.apply_table_sort(self.known_view, ui.get("known_sort_col"), ui.get("known_sort_order"))
        tab = ui.get("tab")
        if tab:
            for i in range(self.tabs.count()):
                if base_tab_name(self.tabs.tabText(i)) == tab:
                    self.tabs.setCurrentIndex(i)
                    break

    def start_prereq_checks(self):
        if not self.ensure_disclaimer():
            return
        self.prereq_model.removeRows(0, self.prereq_model.rowCount())
        tools = self.get_prereq_tools()
        self._prereq_rows = tools
        for tool in tools:
            row = self.prereq_model.rowCount()
            self.prereq_model.insertRow(row)
            item = QtGui.QStandardItem("\U0001F501")
            item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
            self.prereq_model.setItem(row, 0, item)
            self.prereq_model.setItem(row, 1, QtGui.QStandardItem(tool["label"]))
            self.prereq_model.setItem(row, 2, QtGui.QStandardItem(tool.get("path", "")))
        thread = threading.Thread(target=self.prereq_worker, daemon=True)
        thread.start()

    def prereq_worker(self):
        tools = self._prereq_rows
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
            future_map = {}
            for idx, tool in enumerate(tools):
                future_map[exe.submit(self.check_tool, tool)] = idx
            for fut in concurrent.futures.as_completed(future_map):
                idx = future_map[fut]
                ok = safe_result(fut, default=False)
                # Update path column after check
                path = tools[idx].get("path", "")
                self.prereq_row_update.emit(idx, ok, tools[idx]["label"], path)

    def update_prereq_row(self, row, ok, _label, path):
        status_icon = "✅" if ok else "❌"
        item = QtGui.QStandardItem(status_icon)
        item.setForeground(QtGui.QBrush(QtGui.QColor("#1E8E3E" if ok else "#D93025")))
        self.prereq_model.setItem(row, 0, item)
        if path:
            self.prereq_model.setItem(row, 2, QtGui.QStandardItem(path))

    def check_tool(self, tool):
        path = shutil.which(tool["cmd"][0])
        if not path:
            vprint(f"[prereq] missing: {tool['cmd'][0]}")
            return False
        tool["path"] = path
        try:
            vprint(f"[prereq] run: {' '.join(tool['cmd'])}")
            proc = subprocess.run(tool["cmd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            vprint(f"[prereq] {tool['cmd'][0]} -> exit {proc.returncode}")
            return proc.returncode == 0
        except Exception as e:
            vprint(f"[prereq] {tool['cmd'][0]} -> exception: {e}")
            return False

    def get_prereq_tools(self):
        system = platform.system().lower()
        tools = []
        if system == "darwin":
            tools = [
                {"label": "ping", "cmd": ["ping", "-c", "1", "127.0.0.1"]},
                {"label": "arp", "cmd": ["arp", "-an"]},
                {"label": "dscacheutil", "cmd": ["dscacheutil", "-q", "host", "-a", "ip_address", "127.0.0.1"]},
                {"label": "scutil", "cmd": ["scutil", "--dns"]},
                {"label": "route", "cmd": ["route", "-n", "get", "default"]},
                {"label": "ipconfig", "cmd": ["ipconfig", "ifcount"]},
                {"label": "traceroute", "cmd": ["traceroute", "-n", "-m", "1", "127.0.0.1"]},
                {"label": "nslookup", "cmd": ["nslookup", "localhost"]},
            ]
        elif system == "linux":
            tools = [
                {"label": "ping", "cmd": ["ping", "-c", "1", "127.0.0.1"]},
                {"label": "arp", "cmd": ["arp", "-a"]},
                {"label": "getent", "cmd": ["getent", "hosts", "localhost"]},
                {"label": "ip", "cmd": ["ip", "route", "show", "default"]},
                {"label": "traceroute", "cmd": ["traceroute", "-n", "-m", "1", "127.0.0.1"]},
                {"label": "nslookup", "cmd": ["nslookup", "localhost"]},
            ]
        else:
            tools = [
                {"label": "ping", "cmd": ["ping", "-n", "1", "127.0.0.1"]},
                {"label": "arp", "cmd": ["arp", "-a"]},
                {"label": "route", "cmd": ["route", "print", "0.0.0.0"]},
                {"label": "ipconfig", "cmd": ["ipconfig", "/all"]},
                {"label": "tracert", "cmd": ["tracert", "-h", "1", "127.0.0.1"]},
                {"label": "nslookup", "cmd": ["nslookup", "localhost"]},
            ]
        return tools

    def update_tab_counts(self):
        if self._tab_index_devices is not None:
            self.tabs.setTabText(self._tab_index_devices, f"Local Devices ({len(self._rows)})")
        if self._tab_index_known is not None:
            self.tabs.setTabText(self._tab_index_known, f"Known Devices ({len(self._known_store_macs)})")
        if self._tab_index_tasmota is not None:
            self.tabs.setTabText(self._tab_index_tasmota, f"Tasmota Switches ({len(self._tasmota_rows)})")

    def update_web_column(self, row):
        name = self.model.item(row, 3)
        ip_item = self.model.item(row, 0)
        ports_item = self.model.item(row, 6)
        raw = (name.data(self._name_raw_role) if name else "") or ""
        host = raw.strip()
        if not host:
            display = (name.text() if name and name.text() else "").strip()
            if display and not (display.startswith("(") and display.endswith(")")):
                host = display
        if not host:
            host = ip_item.text() if ip_item else ""
        ports = ports_item.text() if ports_item else ""
        url = ""
        if "80" in ports.split(",") or "443" in ports.split(","):
            url = f"http://{host}"
        item = self.model.item(row, 1)
        if item is None:
            item = QtGui.QStandardItem("")
            self.model.setItem(row, 1, item)
        if url:
            item.setText("🌐")
            item.setData(url, QtCore.Qt.UserRole)
            item.setTextAlignment(QtCore.Qt.AlignCenter)
        else:
            item.setText("")
            item.setData("", QtCore.Qt.UserRole)

    def update_known_column(self, row, mac):
        fm = format_mac(mac)
        if not fm:
            return
        raw = fm.replace(":", "").upper()
        item = self.model.item(row, 2)
        if item is None:
            item = QtGui.QStandardItem("")
            self.model.setItem(row, 2, item)
        item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsSelectable)
        self._known_updating = True
        self._known_programmatic += 1
        checked = QtCore.Qt.Checked if raw in self._known_store_macs else QtCore.Qt.Unchecked
        item.setCheckState(checked)
        item.setData(1 if checked == QtCore.Qt.Checked else 0, QtCore.Qt.UserRole)
        QtCore.QTimer.singleShot(0, self._end_known_programmatic_update)
        self._known_updating = False
    def on_known_item_changed(self, item):
        if self._known_updating or self._known_programmatic > 0:
            return
        if item.column() != 2:
            return
        # Ignore initial empty checkbox items with no state
        if item.checkState() not in (QtCore.Qt.Checked, QtCore.Qt.Unchecked):
            return
        mac_item = self.model.item(item.row(), 4)
        if not mac_item:
            return
        raw = format_mac(mac_item.text()).replace(":", "").upper()
        if not raw:
            return
        if item.checkState() == QtCore.Qt.Checked:
            self._known_store_macs.add(raw)
            vprint(f"[netview] known: add {raw}")
        else:
            self._known_store_macs.discard(raw)
            self._known_store_names.pop(raw, None)
            vprint(f"[netview] known: remove {raw}")
        ip_item = self.model.item(item.row(), 0)
        ip = ip_item.text() if ip_item else ""
        self.set_name_item(item.row(), ip)
        self.refresh_known_devices_table()
        self.update_tab_counts()
        self.schedule_config_write()

    def _end_known_programmatic_update(self):
        if self._known_programmatic > 0:
            self._known_programmatic -= 1

    def name_suffixes_for_ip(self, ip):
        suffixes = []
        if self._local_ip and ip == self._local_ip:
            suffixes.append("this machine")
        if self._default_gateway and ip == self._default_gateway:
            suffixes.append("default gateway")
        return suffixes

    def format_display_name(self, raw_name, ip, user_name):
        raw = (raw_name or "").strip()
        display_raw = raw
        if display_raw and not self.show_domain_box.isChecked():
            try:
                ipaddress.ip_address(display_raw)
            except ValueError:
                if "." in display_raw:
                    display_raw = display_raw.split(".", 1)[0]
        base = ""
        user = (user_name or "").strip()
        if user:
            if display_raw:
                base = f"{user} ({display_raw})"
            else:
                base = user
        else:
            base = display_raw
        suffixes = self.name_suffixes_for_ip(ip)
        if not suffixes:
            return base
        suffix = ", ".join(suffixes)
        if base:
            return f"{base} ({suffix})"
        return f"({suffix})"

    def set_name_item(self, row, ip, raw_name=None):
        item = self.model.item(row, 3)
        if item is None:
            item = QtGui.QStandardItem("")
            self.model.setItem(row, 3, item)
        existing = item.data(self._name_raw_role) or ""
        raw = raw_name if raw_name else existing
        user_name = self.user_name_for_row(row, ip)
        self._name_updating = True
        self._name_programmatic += 1
        item.setData(raw or "", self._name_raw_role)
        item.setData(user_name or "", QtCore.Qt.EditRole)
        item.setText(self.format_display_name(raw, ip, user_name))
        flags = item.flags() | QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled
        mac_item = self.model.item(row, 4)
        mac = mac_item.text() if mac_item else ""
        if format_mac(mac):
            flags |= QtCore.Qt.ItemIsEditable
        else:
            flags &= ~QtCore.Qt.ItemIsEditable
        item.setFlags(flags)
        QtCore.QTimer.singleShot(0, self._end_name_programmatic_update)
        self._name_updating = False

    def on_show_domain_changed(self, _state):
        for row in range(self.model.rowCount()):
            ip_item = self.model.item(row, 0)
            ip = ip_item.text() if ip_item else ""
            self.set_name_item(row, ip)
        self.schedule_config_write()

    def on_device_search_changed(self, text):
        self.proxy.set_search(text)

    def on_table_sort_changed(self, _section, _order):
        self.schedule_config_write()

    def apply_table_sort(self, view, col, order):
        if col is None or order is None:
            return
        try:
            col_idx = int(col)
        except Exception:
            return
        ord_val = QtCore.Qt.DescendingOrder if str(order).lower() == "desc" else QtCore.Qt.AscendingOrder
        view.sortByColumn(col_idx, ord_val)

    def refresh_known_devices_table(self):
        self._known_devices_updating = True
        self.known_model.removeRows(0, self.known_model.rowCount())
        known = self._config.get("known_hosts", {}) or {}
        for mac in sorted(self._known_store_macs):
            entry = known.get(mac, ["", "", "", ""])
            if not isinstance(entry, (list, tuple)):
                entry = ["", "", "", ""]
            entry = [str(v) for v in list(entry)[:4]]
            while len(entry) < 4:
                entry.append("")
            user_name = self._known_store_names.get(mac, entry[0])
            dns_name = entry[1]
            ip_addr = entry[2]
            vendor = entry[3]
            row = self.known_model.rowCount()
            self.known_model.insertRow(row)
            values = ["\U0001F5D1\uFE0F", ip_addr, user_name, dns_name, format_mac(mac), vendor]
            for col, val in enumerate(values):
                item = QtGui.QStandardItem(str(val))
                if col == 4:
                    item.setFont(self.mono_font)
                if col == 0:
                    item.setTextAlignment(QtCore.Qt.AlignCenter)
                if col == 2:
                    item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
                else:
                    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
                item.setData(mac, QtCore.Qt.UserRole)
                self.known_model.setItem(row, col, item)
        self.known_view.resizeColumnsToContents()
        header = self.known_view.horizontalHeader()
        header.setStretchLastSection(True)
        self.known_view.setColumnWidth(0, 36)
        self.known_view.sortByColumn(header.sortIndicatorSection(), header.sortIndicatorOrder())
        self._known_devices_updating = False
        self.update_tab_counts()

    def on_known_devices_item_changed(self, item):
        if self._known_devices_updating:
            return
        if item.column() != 2:
            return
        mac = item.data(QtCore.Qt.UserRole) or ""
        mac = str(mac).strip().upper().replace(":", "").replace("-", "")
        if not mac:
            return
        name = (item.text() or "").strip()
        if name:
            self._known_store_names[mac] = name
            self._known_store_macs.add(mac)
            vprint(f"[netview] known: name {mac} -> {name}")
        else:
            self._known_store_names.pop(mac, None)
            vprint(f"[netview] known: name cleared {mac}")
        for ip, row in self._rows.items():
            mac_item = self.model.item(row, 4)
            if not mac_item:
                continue
            if format_mac(mac_item.text()).replace(":", "").upper() == mac:
                self.set_name_item(row, ip)
        self.schedule_config_write()

    def on_known_devices_clicked(self, index):
        if not index.isValid():
            return
        if index.column() != 0:
            return
        item = self.known_model.item(index.row(), 0)
        mac = item.data(QtCore.Qt.UserRole) if item else ""
        mac = str(mac).strip().upper().replace(":", "").replace("-", "")
        if not mac:
            return
        self._known_store_macs.discard(mac)
        self._known_store_names.pop(mac, None)
        vprint(f"[netview] known: remove {mac}")
        self.refresh_known_devices_table()
        for ip, row in self._rows.items():
            mac_item = self.model.item(row, 4)
            if not mac_item:
                continue
            if format_mac(mac_item.text()).replace(":", "").upper() == mac:
                self.update_known_column(row, mac_item.text())
                self.set_name_item(row, ip)
        self.schedule_config_write()

    def user_name_for_row(self, row, ip):
        mac_item = self.model.item(row, 4)
        mac = mac_item.text() if mac_item else ""
        raw_mac = format_mac(mac).replace(":", "").upper() if mac else ""
        if raw_mac and raw_mac in self._known_store_names:
            return self._known_store_names.get(raw_mac, "")
        return ""

    def on_name_item_changed(self, item):
        if self._name_updating or self._name_programmatic > 0:
            return
        if item.column() != 3:
            return
        row = item.row()
        ip_item = self.model.item(row, 0)
        ip = ip_item.text() if ip_item else ""
        user_name = item.data(QtCore.Qt.EditRole)
        if user_name is None:
            user_name = item.text()
        user_name = str(user_name).strip()
        mac_item = self.model.item(row, 4)
        mac = mac_item.text() if mac_item else ""
        raw_mac = format_mac(mac).replace(":", "").upper() if mac else ""
        if raw_mac:
            if user_name:
                self._known_store_names[raw_mac] = user_name
                self._known_store_macs.add(raw_mac)
                vprint(f"[netview] known: name {raw_mac} -> {user_name}")
            else:
                self._known_store_names.pop(raw_mac, None)
                vprint(f"[netview] known: name cleared {raw_mac}")
            self.update_known_column(row, mac)
            self.set_name_item(row, ip)
            self.refresh_known_devices_table()
            self.update_tab_counts()
        self.schedule_config_write()

    def _end_name_programmatic_update(self):
        if self._name_programmatic > 0:
            self._name_programmatic -= 1

    def on_device_clicked(self, index):
        if not index.isValid():
            return
        model = self.view.model()
        if isinstance(model, QtCore.QSortFilterProxyModel):
            source_index = model.mapToSource(index)
            source_model = model.sourceModel()
        else:
            source_index = index
            source_model = model
        if source_index.column() != 1:
            return
        item = source_model.item(source_index.row(), source_index.column())
        url = item.data(QtCore.Qt.UserRole) if item else ""
        if url:
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))

    def on_status_search_changed(self, text):
        self.status_proxy.set_search(text)

    def on_tasmota_search_changed(self, text):
        self.tasmota_proxy.set_search(text)

    def on_known_search_changed(self, text):
        self.known_proxy.set_search(text)

    def on_prereq_search_changed(self, text):
        self.prereq_proxy.set_search(text)

    def on_show_disclaimer_clicked(self):
        self._disclaimer_state = "pending"
        ui = self._config.get("ui", {})
        if "disclaimer_ok" in ui:
            ui.pop("disclaimer_ok", None)
            self._config["ui"] = ui
            write_config(self._config)
        self._disclaimer_shown = False
        self.startup_tasks_with_disclaimer()

    def show_table_context_menu(self, pos):
        view = self.sender()
        if not isinstance(view, QtWidgets.QAbstractItemView):
            return
        index = view.indexAt(pos)
        if not index.isValid():
            return
        model = view.model()
        # Map proxy index to source if needed
        if isinstance(model, QtCore.QSortFilterProxyModel):
            source_index = model.mapToSource(index)
            source_model = model.sourceModel()
        else:
            source_index = index
            source_model = model

        row = source_index.row()
        col = source_index.column()
        cell_text = source_model.data(source_index, QtCore.Qt.DisplayRole)
        header_labels = [source_model.headerData(c, QtCore.Qt.Horizontal) for c in range(source_model.columnCount())]
        web_col = None
        for i, label in enumerate(header_labels):
            if str(label) == "Web":
                web_col = i
                break

        row_values = []
        for c in range(source_model.columnCount()):
            idx = source_model.index(row, c)
            val = source_model.data(idx, QtCore.Qt.DisplayRole)
            if web_col is not None and c == web_col:
                url = source_model.data(idx, QtCore.Qt.UserRole)
                val = url or ""
            row_values.append(val)
        def csv_escape(val):
            s = "" if val is None else str(val)
            if any(ch in s for ch in [",", "\"", "\n"]):
                s = "\"" + s.replace("\"", "\"\"") + "\""
            return s
        row_text = ",".join(csv_escape(v) for v in row_values)

        menu = QtWidgets.QMenu(view)
        copy_cell = menu.addAction("Copy Cell")
        copy_row = menu.addAction("Copy Row")
        action = menu.exec(view.viewport().mapToGlobal(pos))
        if action == copy_cell:
            if web_col is not None and source_index.column() == web_col:
                url = source_model.data(source_index, QtCore.Qt.UserRole)
                QtWidgets.QApplication.clipboard().setText(url or "")
            else:
                QtWidgets.QApplication.clipboard().setText("" if cell_text is None else str(cell_text))
        elif action == copy_row:
            QtWidgets.QApplication.clipboard().setText(row_text)

    def run_status_checks(self):
        vprint("[netview] status: worker start")
        try:
            ping_timeout = int(self.status_timeout.currentText())
        except Exception:
            ping_timeout = 200
        try:
            ping_retries = int(self.status_retries.currentText())
        except Exception:
            ping_retries = 5
        tests = []
        gateway = get_default_gateway()
        vprint(f"[netview] status: gateway={gateway!r}")
        dns_servers = getattr(self, "_status_dns", None) or get_dns_servers()
        vprint(f"[netview] status: dns={dns_servers!r}")
        iface_info = getattr(self, "_iface_info", {}) or {}

        if gateway:
            tests.append(("Local gateway", gateway))
        else:
            tests.append(("Local gateway", ""))

        if not dns_servers:
            tests.append(("DNS server 1", ""))
            tests.append(("DNS server 2", ""))
        else:
            for idx, dns in enumerate(dns_servers):
                tests.append((f"DNS server {idx + 1}", dns))
            if len(dns_servers) == 1:
                tests.append(("DNS server 2", ""))

        tests.extend([
            ("Interface status", "iface"),
            ("DHCP lease", "iface"),
            ("Gateway ARP", "gateway"),
            ("Default route", "gateway"),
            ("DNS system resolve", "heise.de"),
            ("Ping 8.8.8.8", "8.8.8.8"),
            ("Ping 1.1.1.1", "1.1.1.1"),
            ("Ping heise.de", "heise.de"),
            ("TCP 443 heise.de", "heise.de:443"),
            ("HTTP 204 check", "http_204"),
            ("Apple captive check", "http_apple"),
            ("Traceroute 8.8.8.8", "8.8.8.8"),
            ("Reverse lookup 1.1.1.1", "1.1.1.1"),
            ("Reverse lookup 8.8.8.8", "8.8.8.8"),
            ("DNS hijack check", "heise.de"),
        ])

        row_map = getattr(self, "_status_rows", {})
        results = {}
        def run_test(test, host):
            vprint(f"[netview] status: ping {test} -> {host}")
            if test == "Interface status":
                up = iface_info.get("up", False)
                ip = iface_info.get("ip", "")
                netmask = iface_info.get("netmask", "")
                details = f"{iface_info.get('iface','')} {netmask}".strip()
                if not up and not details:
                    details = "interface down or no IP"
                return test, up, details, ip, ""
            if test == "DHCP lease":
                lease = get_dhcp_lease_info(iface_info.get("iface", ""))
                ok = lease not in ("Not supported", "Not available")
                return test, ok, lease, iface_info.get("ip", ""), ""
            if test == "Gateway ARP":
                if not gateway:
                    return test, False, "Not found", "", ""
                arp = parse_arp_table()
                ok = gateway in arp
                return test, ok, arp.get(gateway, {}).get("mac", "not found"), gateway, ""
            if test == "Default route":
                ok = bool(gateway)
                return test, ok, gateway or "Not found", gateway, ""
            if test == "DNS system resolve":
                ip = resolve_host("heise.de")
                ok = bool(ip)
                return test, ok, "" if ok else "resolve failed", ip, ""
            if test.startswith("DNS server"):
                ip = resolve_host_via_dns("heise.de", host)
                ok = bool(ip)
                return test, ok, "" if ok else "resolve failed", ip or host, ""
            if test == "Reverse lookup 1.1.1.1":
                name = reverse_lookup("1.1.1.1")
                ok = bool(name)
                return test, ok, name or "reverse failed", "1.1.1.1", ""
            if test == "Reverse lookup 8.8.8.8":
                name = reverse_lookup("8.8.8.8")
                ok = bool(name)
                return test, ok, name or "reverse failed", "8.8.8.8", ""
            if test == "TCP 443 heise.de":
                ok = tcp_connect("heise.de", 443, timeout=1.5)
                ip = resolve_host("heise.de")
                return test, ok, "" if ok else "connect failed", ip, ""
            if test == "HTTP 204 check":
                ok, msg, ip = http_204_check(timeout=2.0)
                return test, ok, msg if not ok else "", ip, ""
            if test == "Apple captive check":
                ok, msg, ip = http_apple_captive_check(timeout=2.0)
                return test, ok, msg if not ok else "", ip, ""
            if test == "Traceroute 8.8.8.8":
                ok, msg = traceroute_host("8.8.8.8", timeout=3.0)
                return test, ok, msg, "8.8.8.8", ""
            if test == "DNS hijack check":
                ip = resolve_host("heise.de")
                try:
                    ok = bool(ip) and not ipaddress.ip_address(ip).is_private
                except Exception:
                    ok = False
                return test, ok, "" if ok else "private IP", ip, ""

            ok, ms, ip, failed = ping_with_retries(host, timeout_ms=ping_timeout, attempts=ping_retries)
            details = "" if ok else f"{host} timeout"
            if failed:
                details = (details + " " if details else "") + f"failed {failed}/{ping_retries}"
            if ok and failed:
                details = f"had {failed}/{ping_retries} failures"
            ip_show = ip or (host if host and all(c.isdigit() or c == "." for c in host) else "")
            vprint(f"[netview] status: result {test} ok={ok} details={details!r}")
            return test, ok, details, ip_show, ms or ("n/a" if ok else "")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
            for test, host in tests:
                if not host:
                    row = row_map.get(test)
                    if row is not None:
                        self.status_row_update.emit(row, False, "Not found", "", "")
            future_map = {exe.submit(run_test, t, h): t for t, h in tests if h}
            for fut in concurrent.futures.as_completed(future_map):
                test, ok, details, ip_show, ms = safe_result(fut, default=(None, False, "timeout", "", ""))
                if not test:
                    continue
                results[test] = ok
                row = row_map.get(test)
                if row is None:
                    continue
                self.status_row_update.emit(row, ok, details, ip_show, ms)
        vprint("[netview] status: worker done")

        def summarize():
            gw_ok = results.get("Local gateway", False)
            inet_ok = results.get("Ping 8.8.8.8", False) or results.get("Ping 1.1.1.1", False)
            dns_ok = results.get("Ping heise.de", False)
            if not gw_ok:
                return "Local network unreachable"
            if not inet_ok:
                return "Internet unreachable"
            if inet_ok and not dns_ok:
                return "DNS error"
            return "Internet access OK"

        summary = summarize()
        vprint(f"[netview] status: summary={summary}")
        self.status_summary.emit(summary)
        self.status_retry_enable.emit(True)
        self.status_timeout_enable.emit(True)
        self.status_retries_enable.emit(True)
        self._status_running = False
        self.update_tab_counts()

    def on_timeout_changed(self, _index):
        if self.tabs.currentIndex() == self._tab_index_status:
            self.start_status_checks()
        self.schedule_config_write()

    def on_retries_changed(self, _index):
        if self.tabs.currentIndex() == self._tab_index_status:
            self.start_status_checks()
        self.schedule_config_write()

    def on_refresh_changed(self, _index):
        if self.tabs.currentIndex() == self._tab_index_status:
            self.apply_auto_refresh()
        self.schedule_config_write()

    def on_status_timer(self):
        if self.tabs.currentIndex() == self._tab_index_status:
            self.start_status_checks()

    def apply_auto_refresh(self):
        text = self.status_refresh.currentText()
        if text == "Off":
            self.status_timer.stop()
            return
        multipliers = {"s": 1, "m": 60, "h": 3600}
        try:
            if text[-1] in multipliers:
                interval = int(text[:-1]) * multipliers[text[-1]]
            else:
                interval = int(text)
        except Exception:
            self.status_timer.stop()
            return
        self.status_timer.start(interval * 1000)
        if self.tabs.tabText(self.tabs.currentIndex()) == "Network Status":
            self.start_status_checks()


def main():
    parser = argparse.ArgumentParser(description=f"netview {NETVIEW_VERSION} network scanner")
    parser.add_argument("-V", "--version", action="version", version=f"netview {NETVIEW_VERSION}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    args = parser.parse_args()
    global VERBOSE
    VERBOSE = args.verbose
    app = QtWidgets.QApplication([])
    if "macos" in [s.lower() for s in QtWidgets.QStyleFactory.keys()]:
        app.setStyle("macos")
    # Let terminal Ctrl-C terminate the process normally.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    win = NetViewQt()
    win.show()
    app.exec()


if __name__ == "__main__":
    main()
