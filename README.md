<h1 align="center">🛡️ nova-sec-toolkit</h1>
<p align="center"><b>A small ethical-security toolkit in pure Python — for auditing your own systems and learning the blue-team basics.</b><br/>
Port scanning · hash cracking · breach checks · web header recon</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-39ff14?style=for-the-badge&logo=python&logoColor=000000" />
  <img src="https://img.shields.io/badge/tools-4-c6ff00?style=for-the-badge&labelColor=000000" />
  <img src="https://img.shields.io/badge/dependencies-none-39ff14?style=for-the-badge&labelColor=000000" />
</p>

> [!WARNING]
> **Use only on systems you own or have written permission to test.** Scanning, cracking, or probing systems without authorisation is illegal in most countries. These tools are built for learning, CTFs, and auditing your *own* machines and accounts.

## 🧰 Tools

| Command | Tool | What it does |
|---|---|---|
| `scan` | **Port scanner** | Finds open TCP ports and grabs service banners on a host you control |
| `hash` | **Hash toolkit** | Identifies hash types and runs a dictionary (wordlist) crack for CTFs / your own hashes |
| `audit` | **Breach auditor** | Scores password strength and checks Have I Been Pwned — using k-anonymity, so your password never leaves your machine |
| `recon` | **Web recon** | Grades a site's HTTP security headers and flags info disclosure |

## 🚀 Usage

```bash
git clone https://github.com/tanvirkhannova/nova-sec-toolkit.git
cd nova-sec-toolkit

# Scan your own machine
python nova_sec.py scan 127.0.0.1 --ports 1-1024

# Identify and crack a hash (CTF / your own)
python nova_sec.py hash identify 5f4dcc3b5aa765d61d8327deb882cf99
python nova_sec.py hash crack <md5> --wordlist wordlist-sample.txt

# Audit a password (prompts privately, never echoes)
python nova_sec.py audit

# Check your own site's security headers
python nova_sec.py recon https://your-site.com
```

Each tool also runs on its own, e.g. `python port_scanner.py 127.0.0.1`.

## 🔒 Privacy: how the breach check stays safe

The breach auditor uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with **k-anonymity**:

1. It computes the SHA-1 of your password locally.
2. It sends **only the first 5 characters** of that hash to the API.
3. The API returns every hash suffix starting with those 5 chars; the match is checked **on your machine**.

Your password — and even its full hash — never leave your computer.

## 🧪 Tests

```bash
python test_toolkit.py     # runs fully offline, no network needed
```

## 📚 What you can learn from the code

- **Threading** — the port scanner uses a thread pool to scan fast
- **Hashing** — how MD5/SHA families differ, and why dictionary attacks beat weak passwords
- **k-anonymity** — a real privacy-preserving API pattern
- **HTTP security headers** — HSTS, CSP, X-Frame-Options and friends

---

Made by [Tanvir Khan Nova](https://github.com/tanvirkhannova) · MIT License · For educational & authorised use only
