#!/usr/bin/env python3
"""
Password Strength Analyzer
- Entropy calculation
- Regex-based checks (lower/upper/digit/special)
- Optional breach check via Have I Been Pwned (k-anonymity)
- Interactive single-password mode or batch-file mode
- Colored terminal output (optional)
"""

import argparse
import math
import re
import hashlib
import requests
import sys
from getpass import getpass
from pathlib import Path

# Optional colored output
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    COLOR = True
except Exception:
    COLOR = False
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
    class Style:
        RESET_ALL = ''

# Constants
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
DEFAULT_MIN_LENGTH = 8

# ---------- Utilities ----------

def _c(s: str) -> str:
    """Color helper (no-op if color not available)."""
    if not COLOR:
        return s
    return s

# ---------- Core Analysis ----------

def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.
    Determine charset size based on presence of:
     - lowercase (26)
     - uppercase (26)
     - digits (10)
     - punctuation/symbols (common printable)
     - other unicode characters (count as unique)
    Formula: entropy = len(password) * log2(charset_size)
    """
    if not password:
        return 0.0

    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'\d', password):
        charset += 10
    # common ASCII punctuation and symbols
    if re.search(r'[^a-zA-Z0-9]', password):
        # treat as 32 for typical symbol set
        charset += 32

    # fallback: if charset still 0 (e.g., unusual unicode), estimate by unique chars
    if charset == 0:
        charset = len(set(password))
        if charset == 0:
            return 0.0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

def strength_checks(password: str, min_length: int = DEFAULT_MIN_LENGTH) -> dict:
    """
    Return a dict with checks:
      - length_ok (bool)
      - has_lower, has_upper, has_digit, has_special (bool)
      - score (0-5)
    """
    length_ok = len(password) >= min_length
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    score = sum([length_ok, has_lower, has_upper, has_digit, has_special])
    return {
        "length_ok": length_ok,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "score": int(score),
        "length": len(password)
    }

# ---------- HIBP Breach Check ----------

def check_breach_hibp(password: str, timeout: float = 5.0) -> dict:
    """
    Uses HIBP 'range' API (k-anonymity) to check if SHA1 hash suffix appears.
    Returns dict: {found: bool, count: int}
    """
    result = {"found": False, "count": 0, "error": None}
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(HIBP_RANGE_URL.format(prefix), timeout=timeout)
        if resp.status_code != 200:
            result["error"] = f"HIBP error: HTTP {resp.status_code}"
            return result

        # Response contains lines: "HASH_SUFFIX:count"
        for line in resp.text.splitlines():
            if ':' not in line:
                continue
            h_suffix, cnt = line.split(':', 1)
            if h_suffix.upper() == suffix:
                result["found"] = True
                try:
                    result["count"] = int(cnt.strip())
                except ValueError:
                    result["count"] = 0
                return result
        return result
    except requests.RequestException as e:
        result["error"] = f"Network error: {e}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        return result

# ---------- High-level Analyzer ----------

def analyze_password(password: str, do_hibp: bool = True) -> dict:
    """
    Returns full analysis dictionary for a single password.
    """
    res = {}
    res["password_length"] = len(password)
    res["entropy_bits"] = calculate_entropy(password)
    checks = strength_checks(password)
    res.update(checks)

    # qualitative label
    if checks["score"] <= 2 or res["entropy_bits"] < 28:
        res["label"] = "Very Weak"
    elif checks["score"] == 3 or 28 <= res["entropy_bits"] < 50:
        res["label"] = "Weak / Moderate"
    elif checks["score"] == 4 or 50 <= res["entropy_bits"] < 70:
        res["label"] = "Strong"
    else:
        res["label"] = "Very Strong"

    if do_hibp:
        res["hibp"] = check_breach_hibp(password)
    else:
        res["hibp"] = None

    return res

# ---------- Presentation ----------

def pretty_print(result: dict, show_password: bool = False):
    """Print the analysis in a human-friendly way."""
    pwd_len = result.get("password_length", 0)
    entropy = result.get("entropy_bits", 0.0)
    score = result.get("score", 0)
    label = result.get("label", "Unknown")
    hibp = result.get("hibp")

    header = f"Password Analysis (length={pwd_len})"
    print(_c(Fore.BLUE + header + Style.RESET_ALL))

    print(f" • Entropy: {entropy} bits")
    print(f" • Strength Score: {score}/5")
    if label in ("Very Strong", "Strong"):
        print(_c(Fore.GREEN + f" ✔ {label}" + Style.RESET_ALL))
    elif label in ("Weak / Moderate",):
        print(_c(Fore.YELLOW + f" ⚠ {label}" + Style.RESET_ALL))
    else:
        print(_c(Fore.RED + f" ✖ {label}" + Style.RESET_ALL))

    # Components
    comps = []
    comps.append(f"lowercase: {'yes' if result.get('has_lower') else 'no'}")
    comps.append(f"uppercase: {'yes' if result.get('has_upper') else 'no'}")
    comps.append(f"digits: {'yes' if result.get('has_digit') else 'no'}")
    comps.append(f"special: {'yes' if result.get('has_special') else 'no'}")
    print(" • Components: " + ", ".join(comps))

    # HIBP
    if hibp is None:
        print(" • Breach check: (disabled)")
    else:
        if hibp.get("error"):
            print(_c(Fore.YELLOW + f" • Breach check: error — {hibp['error']}" + Style.RESET_ALL))
        elif hibp.get("found"):
            cnt = hibp.get("count", 0)
            print(_c(Fore.RED + f" • Breach check: FOUND in breaches! Seen {cnt} times." + Style.RESET_ALL))
            print(_c(Fore.RED + "   -> Change this password immediately and avoid reuse." + Style.RESET_ALL))
        else:
            print(_c(Fore.GREEN + " • Breach check: Not found in HIBP database." + Style.RESET_ALL))

    if show_password:
        print(f" • Password (raw): {result.get('raw', '')}")

    print("-" * 48)

# ---------- CLI ----------

def parse_args():
    p = argparse.ArgumentParser(description="Password Strength Analyzer")
    group = p.add_mutually_exclusive_group()
    group.add_argument("-p", "--password", help="Password to analyze (use with caution; prefer no-echo input)", type=str)
    group.add_argument("-f", "--file", help="File containing one password per line to analyze as batch", type=Path)
    p.add_argument("--no-hibp", help="Disable Have I Been Pwned breach check", action="store_true")
    p.add_argument("--show-password", help="Show raw password in output (dangerous for shared terminals)", action="store_true")
    p.add_argument("--min-length", help="Minimum recommended password length", type=int, default=DEFAULT_MIN_LENGTH)
    return p.parse_args()

def main():
    args = parse_args()
    do_hibp = not args.no_hibp
    min_length = args.min_length

    if args.password:
        # If password passed on CLI, warn about visibility
        pwd = args.password
    elif args.file:
        # Batch mode
        p = args.file
        if not p.exists():
            print(Fore.RED + f"File not found: {p}" + Style.RESET_ALL)
            sys.exit(1)
        try:
            with p.open("r", encoding="utf-8") as fh:
                for line in fh:
                    pw = line.rstrip("\n\r")
                    if not pw:
                        continue
                    res = analyze_password(pw, do_hibp=do_hibp)
                    res["raw"] = pw
                    pretty_print(res, show_password=args.show_password)
        except Exception as e:
            print(Fore.RED + f"Error reading file: {e}" + Style.RESET_ALL)
            sys.exit(1)
        return
    else:
        # Interactive secure prompt
        try:
            pwd = getpass("Enter password to analyze (input hidden): ")
            if not pwd:
                print("No password entered. Exiting.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    # Analyze single password
    res = analyze_password(pwd, do_hibp=do_hibp)
    res["raw"] = pwd
    pretty_print(res, show_password=args.show_password)

if __name__ == "__main__":
    main()

