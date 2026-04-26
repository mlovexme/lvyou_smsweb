import re
import subprocess
from ipaddress import IPv4Address, IPv4Network, IPv6Address, ip_address, ip_network
from typing import List

from fastapi import HTTPException


def run_command(argv: List[str], timeout: float = 3.0) -> str:
    return subprocess.check_output(argv, stderr=subprocess.DEVNULL, text=True, timeout=timeout).strip()


def guess_ipv4_cidr() -> str:
    try:
        route_text = run_command(["ip", "-4", "route", "show", "default"])
        for line in route_text.splitlines():
            match = re.search(r"dev\s+(\S+)", line)
            if not match:
                continue
            iface = match.group(1)
            addr_text = run_command(["ip", "-4", "addr", "show", "dev", iface])
            for addr_line in addr_text.splitlines():
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", addr_line)
                if m:
                    net = ip_network(m.group(1), strict=False)
                    if isinstance(net, IPv4Network):
                        return f"{net.network_address}/{net.prefixlen}"
            break
    except Exception:
        pass
    try:
        txt = run_command(["ip", "-o", "-4", "addr", "show"])
        for line in txt.splitlines():
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            iface, cidr = parts[1], parts[3]
            if iface == "lo":
                continue
            net = ip_network(cidr, strict=False)
            if isinstance(net, IPv4Network):
                return f"{net.network_address}/{net.prefixlen}"
    except Exception:
        pass
    return "192.168.1.0/24"


def is_device_ip_allowed(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except Exception:
        return False
    if isinstance(addr, IPv4Address):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return False
        return addr.is_private
    if isinstance(addr, IPv6Address):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return False
        return addr.is_private or addr.is_site_local
    return False


def ensure_device_ip_allowed(ip: str) -> None:
    if not is_device_ip_allowed(ip):
        raise HTTPException(status_code=400, detail="设备 IP 不在允许的内网范围内")
