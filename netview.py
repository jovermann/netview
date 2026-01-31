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

from PySide6 import QtCore, QtGui, QtWidgets
import signal

VERBOSE = 0


def vprint(msg, level=1):
    if VERBOSE >= level:
        print(msg, flush=True)


def base_tab_name(text: str) -> str:
    return text.split(" (", 1)[0].strip()


def load_config():
    path = Path.home() / ".netviewrc.toml"
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text())
    except Exception:
        return {}


def extract_known_hosts(cfg):
    macs = cfg.get("known_hosts", {}).get("macs", [])
    out = set()
    for m in macs:
        m = str(m).strip().upper().replace(":", "").replace("-", "")
        if m:
            out.add(m)
    return out


def write_config(cfg):
    path = Path.home() / ".netviewrc.toml"
    lines = []
    # known hosts
    macs = sorted(cfg.get("known_hosts", {}).get("macs", []))
    lines.append("[known_hosts]")
    lines.append("macs = [")
    for m in macs:
        lines.append(f'  "{m}",')
    lines.append("]")
    lines.append("")
    # ui settings
    ui = cfg.get("ui", {})
    lines.append("[ui]")
    lines.append(f'tab = "{ui.get("tab", "Network Status")}"')
    lines.append(f'status_auto = "{ui.get("status_auto", "Off")}"')
    lines.append(f'devices_auto = "{ui.get("devices_auto", "Off")}"')
    lines.append(f'tasmota_auto = "{ui.get("tasmota_auto", "Off")}"')
    lines.append(f'ping_timeout = "{ui.get("ping_timeout", "200")}"')
    lines.append(f'ping_retries = "{ui.get("ping_retries", "5")}"')
    try:
        path.write_text("\n".join(lines) + "\n")
    except Exception:
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
            lstate = left.data(QtCore.Qt.CheckStateRole) == QtCore.Qt.Checked
            rstate = right.data(QtCore.Qt.CheckStateRole) == QtCore.Qt.Checked
            return (0 if not lstate else 1) < (0 if not rstate else 1)
        if col == 6:
            return ports_key(lval) < ports_key(rval)
        return str(lval).lower() < str(rval).lower()


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
    prereq_row_update = QtCore.Signal(int, bool, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("netview")
        self.resize(1300, 820)

        self._oui_db = load_oui_db()
        self._rows = {}
        self._scan_count = 0
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
        self.view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
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
        status_bar.addWidget(self.status_retry)
        status_bar.addWidget(QtWidgets.QLabel("Ping timeout (ms):"))
        status_bar.addWidget(self.status_timeout)
        status_bar.addWidget(QtWidgets.QLabel("Retries:"))
        status_bar.addWidget(self.status_retries)
        status_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        status_bar.addWidget(self.status_refresh)
        status_bar.addWidget(self.status_text)
        status_bar.addStretch(1)
        status_layout.addLayout(status_bar)

        self.status_model = QtGui.QStandardItemModel(0, 5, self)
        self.status_model.setHorizontalHeaderLabels(["Status", "Test", "IP", "Ping", "Details"])

        self.status_view = QtWidgets.QTableView()
        self.status_view.setModel(self.status_model)
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
        tasmota_bar.addWidget(self.tasmota_rescan)
        tasmota_bar.addWidget(self.tasmota_refresh)
        tasmota_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        tasmota_bar.addWidget(self.tasmota_refresh_box)
        tasmota_bar.addStretch(1)
        tasmota_layout.addLayout(tasmota_bar)

        self.tasmota_model = QtGui.QStandardItemModel(0, 11, self)
        self.tasmota_model.setHorizontalHeaderLabels(
            ["Name", "State", "Switch", "Web", "IP", "Power", "Today", "Yesterday", "Total", "WiFi", "Details"]
        )
        self.tasmota_view = QtWidgets.QTableView()
        self.tasmota_view.setModel(self.tasmota_model)
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
        self.status = QtWidgets.QLabel("Idle")
        self.devices_refresh_box = QtWidgets.QComboBox()
        self.devices_refresh_box.addItems(["Off", "10s", "15s", "20s", "30s", "60s", "2m", "5m", "10m", "30m", "1h"])
        self.devices_refresh_box.setCurrentText("Off")
        self.devices_refresh_box.currentIndexChanged.connect(self.on_devices_refresh_changed)
        devices_bar.addWidget(self.refresh_btn)
        devices_bar.addWidget(QtWidgets.QLabel("Auto-Refresh:"))
        devices_bar.addWidget(self.devices_refresh_box)
        devices_bar.addWidget(self.status)
        devices_bar.addStretch(1)
        devices_layout.addLayout(devices_bar)

        devices_layout.addWidget(self.view)

        self._tab_index_devices = self.tabs.addTab(devices_tab, "Local Devices")
        self._tab_index_tasmota = self.tabs.addTab(tasmota_tab, "Tasmota Switches")

        prereq_tab = QtWidgets.QWidget()
        prereq_layout = QtWidgets.QVBoxLayout(prereq_tab)
        prereq_layout.setContentsMargins(8, 8, 8, 8)
        prereq_layout.setSpacing(10)

        self.prereq_model = QtGui.QStandardItemModel(0, 3, self)
        self.prereq_model.setHorizontalHeaderLabels(["Status", "Tool", "Path"])
        self.prereq_view = QtWidgets.QTableView()
        self.prereq_view.setModel(self.prereq_model)
        self.prereq_view.horizontalHeader().setStretchLastSection(True)
        self.prereq_view.verticalHeader().setVisible(False)
        self.prereq_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.prereq_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.prereq_view.setShowGrid(False)
        self.prereq_view.setAlternatingRowColors(True)
        self.prereq_view.setWordWrap(False)
        prereq_layout.addWidget(self.prereq_view)
        self._tab_index_prereq = self.tabs.addTab(prereq_tab, "Prerequisites")

        base_font = QtGui.QFont()
        base_font.setPointSize(13)
        self.setFont(base_font)
        self.status.setFont(base_font)
        self.view.setFont(base_font)
        self.status_view.setFont(base_font)
        self.tasmota_view.setFont(base_font)
        self.prereq_view.setFont(base_font)
        self.mono_font = QtGui.QFont("Menlo", 12)
        self.view.verticalHeader().setDefaultSectionSize(28)
        self.ensure_device_column_widths()
        self.tasmota_view.verticalHeader().setDefaultSectionSize(28)
        self.prereq_view.verticalHeader().setDefaultSectionSize(28)

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
        self._config = load_config()
        self._known_macs = extract_known_hosts(self._config)
        self._known_updating = False
        self.model.itemChanged.connect(self.on_known_item_changed)
        self._config_timer = QtCore.QTimer(self)
        self._config_timer.setSingleShot(True)
        self._config_timer.timeout.connect(self.flush_config)

        # Allow quitting with Ctrl+C even when the app has focus.
        QtWidgets.QApplication.instance().installEventFilter(self)

        self.tabs.currentChanged.connect(self.on_tab_changed)
        self._status_initialized = False
        QtCore.QTimer.singleShot(100, self.start_status_checks)
        QtCore.QTimer.singleShot(120, self.start_scan)
        QtCore.QTimer.singleShot(140, self.start_tasmota_scan)
        QtCore.QTimer.singleShot(160, self.start_prereq_checks)
        QtCore.QTimer.singleShot(200, self.raise_)
        QtCore.QTimer.singleShot(250, self.activateWindow)
        self.apply_saved_ui()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_C and (event.modifiers() & QtCore.Qt.ControlModifier):
                QtWidgets.QApplication.quit()
                return True
        return super().eventFilter(obj, event)

    def start_scan(self):
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
                self.model.setItem(row, col, item)
            else:
                item.setText(str(val))
                if col == 5 and str(val).startswith("(") and str(val).endswith(")"):
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#6E6E73")))
        self.set_name_item(row, ip, name)
        self.update_web_column(row)
        self.update_known_column(row, mac)
        self._known_updating = False
        self.view.sortByColumn(0, QtCore.Qt.AscendingOrder)
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

    def start_status_checks(self):
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
        # Keep sorted by Name
        self.tasmota_view.sortByColumn(0, QtCore.Qt.AscendingOrder)

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
        ui["tasmota_auto"] = self.tasmota_refresh_box.currentText()
        ui["ping_timeout"] = self.status_timeout.currentText()
        ui["ping_retries"] = self.status_retries.currentText()
        self._config["ui"] = ui
        self._config["known_hosts"] = {"macs": sorted(self._known_macs)}
        write_config(self._config)

    def apply_saved_ui(self):
        ui = self._config.get("ui", {})
        if ui.get("status_auto"):
            self.status_refresh.setCurrentText(ui.get("status_auto"))
        if ui.get("devices_auto"):
            self.devices_refresh_box.setCurrentText(ui.get("devices_auto"))
        if ui.get("tasmota_auto"):
            self.tasmota_refresh_box.setCurrentText(ui.get("tasmota_auto"))
        if ui.get("ping_timeout"):
            self.status_timeout.setCurrentText(ui.get("ping_timeout"))
        if ui.get("ping_retries"):
            self.status_retries.setCurrentText(ui.get("ping_retries"))
        tab = ui.get("tab")
        if tab:
            for i in range(self.tabs.count()):
                if base_tab_name(self.tabs.tabText(i)) == tab:
                    self.tabs.setCurrentIndex(i)
                    break

    def start_prereq_checks(self):
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
                self.prereq_row_update.emit(idx, ok, tools[idx]["label"])
                if path:
                    self.prereq_model.setItem(idx, 2, QtGui.QStandardItem(path))

    def update_prereq_row(self, row, ok, _label):
        status_icon = "✅" if ok else "❌"
        item = QtGui.QStandardItem(status_icon)
        item.setForeground(QtGui.QBrush(QtGui.QColor("#1E8E3E" if ok else "#D93025")))
        self.prereq_model.setItem(row, 0, item)

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
        item.setCheckState(QtCore.Qt.Checked if raw in self._known_macs else QtCore.Qt.Unchecked)
        self._known_updating = False

    def on_known_item_changed(self, item):
        if self._known_updating:
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
            self._known_macs.add(raw)
        else:
            self._known_macs.discard(raw)
        self.schedule_config_write()

    def name_suffixes_for_ip(self, ip):
        suffixes = []
        if self._local_ip and ip == self._local_ip:
            suffixes.append("this machine")
        if self._default_gateway and ip == self._default_gateway:
            suffixes.append("default gateway")
        return suffixes

    def format_display_name(self, raw_name, ip):
        raw = (raw_name or "").strip()
        suffixes = self.name_suffixes_for_ip(ip)
        if not suffixes:
            return raw
        suffix = ", ".join(suffixes)
        if raw:
            return f"{raw} ({suffix})"
        return f"({suffix})"

    def set_name_item(self, row, ip, raw_name=None):
        item = self.model.item(row, 3)
        if item is None:
            item = QtGui.QStandardItem("")
            self.model.setItem(row, 3, item)
        existing = item.data(self._name_raw_role) or ""
        raw = raw_name if raw_name else existing
        item.setData(raw or "", self._name_raw_role)
        item.setText(self.format_display_name(raw, ip))

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
    parser = argparse.ArgumentParser(description="netview network scanner")
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
