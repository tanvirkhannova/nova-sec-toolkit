"""Offline tests — run with `python test_toolkit.py` (no network needed)."""
import hashlib
import tempfile

import breach_auditor
import hash_tools
import port_scanner
import web_recon


def test_port_scanner():
    assert port_scanner.parse_ports("20-22,80") == [20, 21, 22, 80]


def test_hash_tools():
    assert "md5" in hash_tools.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    wl.write("admin\npassword\n")
    wl.close()
    assert hash_tools.crack(hashlib.md5(b"password").hexdigest(), wl.name) == "password"


def test_breach_auditor():
    assert breach_auditor.strength("password")["label"].startswith("very weak")
    sha1 = hashlib.sha1(b"hunter2").hexdigest().upper()
    assert len(sha1[:5]) == 5


def test_web_recon():
    assert web_recon.grade(6, 6) == "A"
    assert web_recon.grade(0, 6) == "F"


if __name__ == "__main__":
    test_port_scanner()
    test_hash_tools()
    test_breach_auditor()
    test_web_recon()
    print("✔ all tests passed")
