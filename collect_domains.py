#!/usr/bin/env python3
"""Build a .ke domain list from PUBLIC sources only.

Sources:
  1. Certificate Transparency (crt.sh) - any name that ever appeared on a public TLS cert
  2. Optional: a Tranco top-sites CSV (https://tranco-list.eu) filtered to .ke

Note: KENIC does not publish the .ke zone file, so this is a *sample* of
the namespace biased toward domains that use HTTPS. State this in your report.
"""
import argparse
import time

import requests

UA = "ke-mailshield-research/1.0 (+https://github.com/<your-username>/ke-mailshield)"
SLDS = ["co", "or", "ne", "go", "ac", "sc", "me", "mobi", "info"]
QUERIES = [f"{s}.ke" for s in SLDS] + ["ke"]


def registrable(name):
    name = name.lower().strip().lstrip("*.").rstrip(".")
    parts = name.split(".")
    if len(parts) < 2 or parts[-1] != "ke":
        return None
    if len(parts) >= 3 and parts[-2] in SLDS:
        return ".".join(parts[-3:])
    if parts[-2] not in SLDS:
        return ".".join(parts[-2:])
    return None


def from_crtsh(suffix, retries=3):
    for i in range(retries):
        try:
            r = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{suffix}", "output": "json"},
                headers={"User-Agent": UA},
                timeout=180,
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:  # crt.sh is slow/flaky; just retry
            print(f"  retry {i + 1} for {suffix}: {e}")
        time.sleep(10 * (i + 1))
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/domains.txt")
    ap.add_argument("--tranco", help="path to Tranco CSV (rank,domain)")
    args = ap.parse_args()

    domains = set()
    for suffix in QUERIES:
        print(f"[crt.sh] %.{suffix}")
        for row in from_crtsh(suffix):
            for n in row.get("name_value", "").split("\n"):
                d = registrable(n)
                if d:
                    domains.add(d)
        print(f"  total so far: {len(domains)}")
        time.sleep(3)

    if args.tranco:
        with open(args.tranco) as f:
            for line in f:
                d = registrable(line.strip().split(",")[-1])
                if d:
                    domains.add(d)

    with open(args.out, "w") as f:
        f.write("\n".join(sorted(domains)) + "\n")
    print(f"Wrote {len(domains)} domains to {args.out}")


if __name__ == "__main__":
    main()
