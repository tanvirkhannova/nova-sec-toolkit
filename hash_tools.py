"""Hash identifier + dictionary cracker — for CTFs and auditing hashes YOU own.

    python hash_tools.py identify 5f4dcc3b5aa765d61d8327deb882cf99
    python hash_tools.py crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist words.txt
    echo -n "hello" | python hash_tools.py make --algo sha256

Only crack hashes you are authorised to recover. This is a dictionary attack only:
it tries words from a list, it does not break strong, salted or slow hashes.
"""
import argparse
import hashlib
import sys

BY_LENGTH = {32: ["md5", "ntlm (if uppercase hex)"], 40: ["sha1"], 56: ["sha224"],
             64: ["sha256"], 96: ["sha384"], 128: ["sha512"]}


def identify(h):
    h = h.strip().lower()
    if not all(c in "0123456789abcdef" for c in h):
        return ["not plain hex — could be bcrypt ($2...), argon2 ($argon2...), or base64"]
    return BY_LENGTH.get(len(h), [f"unknown ({len(h)} hex chars)"])


def make(text, algo):
    return hashlib.new(algo, text.encode()).hexdigest()


def crack(target, wordlist_path, algos=("md5", "sha1", "sha256")):
    target = target.strip().lower()
    guessed_algos = [a for a in algos if len(hashlib.new(a).hexdigest()) == len(target)] or algos
    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            word = line.rstrip("\n")
            for algo in guessed_algos:
                if hashlib.new(algo, word.encode()).hexdigest() == target:
                    print(f"[FOUND] {algo}: '{word}'  (after {i} tries)")
                    return word
    print(f"[NOT FOUND] exhausted wordlist ({i} words).")
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Identify, make or dictionary-crack hashes you own.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_id = sub.add_parser("identify"); p_id.add_argument("hash")
    p_mk = sub.add_parser("make"); p_mk.add_argument("text", nargs="?"); p_mk.add_argument("--algo", default="sha256")
    p_cr = sub.add_parser("crack"); p_cr.add_argument("hash"); p_cr.add_argument("--wordlist", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "identify":
        print("Possible types:", ", ".join(identify(args.hash)))
    elif args.cmd == "make":
        text = args.text if args.text is not None else sys.stdin.read().rstrip("\n")
        print(make(text, args.algo))
    elif args.cmd == "crack":
        crack(args.hash, args.wordlist)


if __name__ == "__main__":
    main()
