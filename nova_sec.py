"""nova-sec-toolkit launcher — pick a tool.

    python nova_sec.py scan 127.0.0.1
    python nova_sec.py hash identify <hash>
    python nova_sec.py audit
    python nova_sec.py recon https://example.com
"""
import sys

MENU = {"scan": "port_scanner", "hash": "hash_tools", "audit": "breach_auditor", "recon": "web_recon"}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in MENU:
        print(__doc__)
        print("Tools:", ", ".join(MENU))
        return 1
    module = __import__(MENU[sys.argv[1]])
    module.main(sys.argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
