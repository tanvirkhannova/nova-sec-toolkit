"""Password strength + breach auditor.

    python breach_auditor.py              # prompts privately, never echoes
    python breach_auditor.py "P@ssw0rd"   # or pass directly (less private)

Breach check uses the Have I Been Pwned range API with k-anonymity: only the first
5 characters of the password's SHA-1 are ever sent, never the password itself.
"""
import argparse
import getpass
import hashlib
import math
import string
import sys
from urllib.request import urlopen, Request

COMMON = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou", "monkey"}
API = "https://api.pwnedpasswords.com/range/"


def entropy_bits(pw: str) -> float:
    pool = (26 * any(c.islower() for c in pw) + 26 * any(c.isupper() for c in pw)
            + 10 * any(c.isdigit() for c in pw) + len(string.punctuation) * any(c in string.punctuation for c in pw))
    return round(len(pw) * math.log2(pool), 1) if pool else 0.0


def strength(pw: str) -> dict:
    bits = entropy_bits(pw)
    score = 0 if bits < 28 else 1 if bits < 36 else 2 if bits < 60 else 3 if bits < 80 else 4
    label = ["very weak", "weak", "fair", "strong", "very strong"][score]
    if pw.lower() in COMMON:
        label, bits = "very weak (common password)", 0.0
    return {"entropy": bits, "label": label}


def pwned_count(pw: str, timeout=10) -> int:
    """Return how many breaches contain this password (0 = not found). Uses k-anonymity."""
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = Request(API + prefix, headers={"User-Agent": "nova-sec-toolkit"})
    body = urlopen(req, timeout=timeout).read().decode()          # only the 5-char prefix leaves your machine
    for line in body.splitlines():
        tail, count = line.split(":")
        if tail == suffix:
            return int(count)
    return 0


def audit(pw: str, online=True) -> dict:
    result = strength(pw)
    if online:
        try:
            n = pwned_count(pw)
            result["breaches"] = n
            result["verdict"] = "SAFE (not in known breaches)" if n == 0 else f"EXPOSED in {n:,} breaches — change it"
        except Exception as e:
            result["verdict"] = f"could not reach breach API: {e}"
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit a password's strength and breach exposure.")
    ap.add_argument("password", nargs="?")
    ap.add_argument("--offline", action="store_true", help="skip the breach check")
    args = ap.parse_args(argv)
    pw = args.password or getpass.getpass("Password (hidden): ")
    if not pw:
        sys.exit("No password given.")
    r = audit(pw, online=not args.offline)
    print(f"Strength : {r['label']} (~{r['entropy']} bits)")
    if "verdict" in r:
        print(f"Breaches : {r['verdict']}")


if __name__ == "__main__":
    main()
