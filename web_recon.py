"""Web recon — check security headers on a site YOU own or are authorised to test.

    python web_recon.py https://example.com

Reports which recommended HTTP security headers are present or missing, the server
banner, and a simple grade. Only point this at sites you own or have permission to test.
"""
import argparse
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError

RECOMMENDED = {
    "strict-transport-security": "forces HTTPS (HSTS)",
    "content-security-policy": "limits where scripts/resources load from (XSS defence)",
    "x-frame-options": "blocks clickjacking via iframes",
    "x-content-type-options": "stops MIME-type sniffing",
    "referrer-policy": "controls how much referrer info leaks",
    "permissions-policy": "restricts browser features (camera, geolocation…)",
}
LEAKY = {"server": "reveals server software/version", "x-powered-by": "reveals backend tech"}


def fetch_headers(url, timeout=10):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = Request(url, headers={"User-Agent": "nova-sec-toolkit/1.0"}, method="HEAD")
    try:
        resp = urlopen(req, timeout=timeout)
    except URLError:
        resp = urlopen(Request(url, headers={"User-Agent": "nova-sec-toolkit/1.0"}), timeout=timeout)
    return {k.lower(): v for k, v in resp.getheaders()}, resp.status, resp.geturl()


def grade(present, total):
    pct = present / total
    return "A" if pct >= 0.85 else "B" if pct >= 0.6 else "C" if pct >= 0.4 else "D" if pct else "F"


def report(url):
    headers, status, final = fetch_headers(url)
    print(f"Target : {final}  (HTTP {status})\n")
    present = 0
    print("Security headers:")
    for h, why in RECOMMENDED.items():
        ok = h in headers
        present += ok
        print(f"  [{'OK' if ok else 'XX'}] {h:<28} {'' if ok else '— missing: ' + why}")
    print(f"\nGrade: {grade(present, len(RECOMMENDED))}  ({present}/{len(RECOMMENDED)} present)")
    leaks = {h: headers[h] for h in LEAKY if h in headers}
    if leaks:
        print("\nInformation disclosure:")
        for h, v in leaks.items():
            print(f"  [!] {h}: {v}  — {LEAKY[h]}")
    return headers


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check a site's HTTP security headers.")
    ap.add_argument("url")
    args = ap.parse_args(argv)
    try:
        report(args.url)
    except Exception as e:
        sys.exit(f"Could not fetch {args.url}: {e}")


if __name__ == "__main__":
    main()
