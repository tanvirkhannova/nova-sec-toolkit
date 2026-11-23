"""Port scanner — find open TCP ports on a host YOU own or are authorised to test.

    python port_scanner.py 127.0.0.1
    python port_scanner.py 192.168.1.10 --ports 1-1024
    python port_scanner.py scanme.nmap.org --ports 20,22,80,443

Scanning systems you do not own or have written permission to test may be illegal.
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

COMMON = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
          80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
          3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt"}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan_port(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        banner = ""
        try:
            s.settimeout(0.5)
            banner = s.recv(64).decode("latin-1", "replace").strip().split("\n")[0]
        except OSError:
            pass
        return port, banner


def scan(host, ports, timeout=0.5, workers=200):
    ip = socket.gethostbyname(host)
    print(f"Scanning {host} ({ip}) — {len(ports)} ports\n")
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(lambda p: scan_port(ip, p, timeout), ports):
            if result:
                port, banner = result
                name = COMMON.get(port, "unknown")
                print(f"  [OPEN] {port:>5}/{name:<10} {banner}")
                open_ports.append(port)
    print(f"\n{len(open_ports)} open port(s): {open_ports}")
    return open_ports


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan a host you own for open TCP ports.")
    ap.add_argument("host")
    ap.add_argument("--ports", default="1-1024", help="e.g. 1-1024 or 22,80,443")
    ap.add_argument("--timeout", type=float, default=0.5)
    args = ap.parse_args(argv)
    try:
        scan(args.host, parse_ports(args.ports), args.timeout)
    except socket.gaierror:
        sys.exit(f"Could not resolve host: {args.host}")
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")


if __name__ == "__main__":
    main()
