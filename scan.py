#!/usr/bin/env python3
"""Passive email-security scanner.

Only sends DNS queries (via public resolvers) and, optionally, one HTTPS GET for
the *intentionally public* MTA-STS policy file. No SMTP connections, no port
scanning, no authentication attempts.
"""
import argparse
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver
import requests

UA = "ke-mailshield-research/1.0 (+https://github.com/<your-username>/ke-mailshield)"
NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
# DKIM selectors can't be enumerated, so detection is a LOWER BOUND.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "mail", "dkim", "smtp", "zoho", "zmail", "mandrill", "mxvault", "cm",
    "sendgrid", "mailjet", "amazonses",
]
PROVIDERS = [
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"), ("zoho.", "Zoho"), ("mimecast", "Mimecast"),
    ("pphosted", "Proofpoint"), ("mailgun", "Mailgun"), ("yandex", "Yandex"),
    ("protonmail", "Proton"), ("secureserver.net", "GoDaddy"),
    ("hostinger", "Hostinger"), ("titan.email", "Titan"), ("icloud", "iCloud"),
]
_local = threading.local()


def resolver():
    r = getattr(_local, "r", None)
    if r is None:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = NAMESERVERS
        r.timeout = 3
        r.lifetime = 8
        _local.r = r
    return r


def q(name, rtype):
    try:
        return "ok", list(resolver().resolve(name, rtype))
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "noanswer", []
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return "error", []
    except Exception:
        return "error", []


def txt(name):
    st, ans = q(name, "TXT")
    return st, [b"".join(r.strings).decode("utf-8", "ignore") for r in ans]


def spf_lookups(rec, seen, depth=0):
    """Approximate count of DNS-lookup mechanisms (RFC 7208 limit is 10)."""
    if depth > 5:
        return 0
    n = 0
    for t in rec.split()[1:]:
        t = t.lstrip("+-~?")
        if t.startswith(("include:", "redirect=")):
            n += 1
            target = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            _, recs = txt(target)
            sub = [x for x in recs if x.lower().startswith("v=spf1")]
            if sub:
                n += spf_lookups(sub[0].lower(), seen, depth + 1)
        elif t.startswith(("a:", "a/", "mx:", "mx/", "exists:", "ptr")) or t in ("a", "mx"):
            n += 1
    return n


def parse_tags(rec):
    tags = {}
    for part in rec.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip()
    return tags


def classify_provider(hosts):
    joined = " ".join(hosts)
    for needle, name in PROVIDERS:
        if needle in joined:
            return name
    return "Other / self-hosted" if hosts else None


def scan(domain, dkim=True, http=True):
    row = {"domain": domain}
    st, _ = q(domain, "NS")
    row["alive"] = st != "nxdomain"
    if st == "nxdomain":
        return row

    # MX
    _, mx = q(domain, "MX")
    hosts = sorted((r.preference, str(r.exchange).rstrip(".").lower()) for r in mx)
    row["null_mx"] = any(p == 0 and h == "" for p, h in hosts)
    row["mx"] = [h for _, h in hosts if h]
    row["has_mx"] = bool(row["mx"])
    row["provider"] = classify_provider(row["mx"])

    # SPF
    _, recs = txt(domain)
    spf = [t for t in recs if t.lower().startswith("v=spf1")]
    row["spf_present"] = bool(spf)
    row["spf_multiple"] = len(spf) > 1  # invalid per RFC 7208 -> permerror
    if spf:
        rec = spf[0]
        row["spf_record"] = rec
        m = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", rec.lower())
        row["spf_all"] = (m.group(1) or "+") if m else None
        row["spf_lookups"] = spf_lookups(rec.lower(), {domain})

    # DMARC
    _, d = txt(f"_dmarc.{domain}")
    dm = [t for t in d if t.lower().startswith("v=dmarc1")]
    row["dmarc_present"] = bool(dm)
    if dm:
        tags = parse_tags(dm[0])
        row["dmarc_p"] = tags.get("p", "").lower() or None
        row["dmarc_sp"] = tags.get("sp", "").lower() or None
        row["dmarc_pct"] = int(tags["pct"]) if tags.get("pct", "").isdigit() else 100
        row["dmarc_rua"] = tags.get("rua") or None
        row["dmarc_ruf"] = tags.get("ruf") or None

    # DKIM (lower bound)
    if dkim and row["has_mx"]:
        found = []
        for s in DKIM_SELECTORS:
            _, t = txt(f"{s}._domainkey.{domain}")
            if any("p=" in x.lower() or "v=dkim1" in x.lower() for x in t):
                found.append(s)
        row["dkim_selectors"] = found

    # MTA-STS, TLS-RPT, BIMI
    _, t = txt(f"_mta-sts.{domain}")
    row["mta_sts_dns"] = any(x.lower().startswith("v=stsv1") for x in t)
    if http and row["mta_sts_dns"]:
        try:
            r = requests.get(
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                timeout=6, allow_redirects=False, headers={"User-Agent": UA},
            )
            if r.status_code == 200:
                m = re.search(r"^mode:\s*(\w+)", r.text, re.M | re.I)
                row["mta_sts_mode"] = m.group(1).lower() if m else None
        except Exception:
            pass
    _, t = txt(f"_smtp._tls.{domain}")
    row["tls_rpt"] = any(x.lower().startswith("v=tlsrptv1") for x in t)
    _, t = txt(f"default._bimi.{domain}")
    row["bimi"] = any(x.lower().startswith("v=bimi1") for x in t)

    # DNSSEC (DS at parent) and CAA
    st, _ = q(domain, "DS")
    row["dnssec"] = st == "ok"
    st, _ = q(domain, "CAA")
    row["caa"] = st == "ok"
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", default="data/domains.txt")
    ap.add_argument("--out", default="data/results.jsonl")
    ap.add_argument("--workers", type=int, default=30, help="keep modest; be polite to resolvers")
    ap.add_argument("--no-dkim", action="store_true")
    ap.add_argument("--no-http", action="store_true", help="skip MTA-STS policy fetch")
    args = ap.parse_args()

    with open(args.domains) as f:
        domains = [l.strip().lower() for l in f if l.strip()]
    done = set()
    if os.path.exists(args.out):  # resume support
        with open(args.out) as f:
            done = {json.loads(l)["domain"] for l in f if l.strip()}
    todo = [d for d in domains if d not in done]
    print(f"{len(todo)} to scan ({len(done)} already done)")

    with open(args.out, "a") as out, ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(scan, d, not args.no_dkim, not args.no_http): d for d in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                out.write(json.dumps(fut.result()) + "\n")
            except Exception as e:
                out.write(json.dumps({"domain": futs[fut], "error": str(e)}) + "\n")
            if i % 100 == 0:
                out.flush()
                print(f"  {i}/{len(todo)}")


if __name__ == "__main__":
    main()
