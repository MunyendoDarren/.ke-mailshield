#!/usr/bin/env python3
"""Turn raw scan results into scores, tables and charts (aggregates only)."""
import argparse

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SECTORS = {
    "co.ke": "Commercial", "or.ke": "Organisations/NGOs", "go.ke": "Government",
    "ac.ke": "Academia", "sc.ke": "Schools", "ne.ke": "Networks",
    "me.ke": "Personal", "info.ke": "Info", "mobi.ke": "Mobile", "ke": "Direct .ke",
}


def has(x):
    return isinstance(x, (list, str)) and len(x) > 0


def score(r):
    """0-100 email-hardening score (transparent, documented in README)."""
    s = 0
    if r["spf_present"]:
        s += {"-": 20, "~": 15}.get(r.get("spf_all"), 5)
        lk = r.get("spf_lookups")
        if (pd.isna(lk) or lk <= 10) and not r["spf_multiple"]:
            s += 5
    s += {"none": 10, "quarantine": 25, "reject": 35}.get(r.get("dmarc_p"), 0)
    if has(r.get("dmarc_rua")):
        s += 5
    if has(r.get("dkim_selectors")):
        s += 10
    s += {"enforce": 10, "testing": 5}.get(r.get("mta_sts_mode"), 0)
    s += 5 if r["tls_rpt"] else 0
    s += 10 if r["dnssec"] else 0
    return s


def md(df):
    return df.to_markdown(floatfmt=".1f")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/results.jsonl")
    ap.add_argument("--min-group", type=int, default=30)
    args = ap.parse_args()

    df = pd.read_json(args.inp, lines=True)
    boolcols = ["alive", "has_mx", "null_mx", "spf_present", "spf_multiple",
                "dmarc_present", "mta_sts_dns", "tls_rpt", "bimi", "dnssec", "caa"]
    for c in boolcols:
        if c not in df:
            df[c] = False
        df[c] = df[c].fillna(False).astype(bool)
    for c in ["spf_all", "dmarc_p", "mta_sts_mode", "provider", "spf_lookups",
              "dkim_selectors", "dmarc_rua"]:
        if c not in df:
            df[c] = None

    total = len(df)
    df = df[df.alive].copy()
    live = len(df)
    m = df[df.has_mx & ~df.null_mx].copy()
    m["zone"] = m.domain.str.split(".", n=1).str[1]
    m["sector"] = m.zone.map(SECTORS).fillna("Other")
    m["score"] = m.apply(score, axis=1)
    m["dmarc_enforced"] = m.dmarc_p.isin(["quarantine", "reject"])
    m["dkim_found"] = m.dkim_selectors.apply(has)
    m["spf_strict"] = m.spf_all.isin(["-", "~"])
    m["spoofable"] = ~m.dmarc_enforced
    m.drop(columns=["mx"], errors="ignore").to_csv("data/scored_domains.csv", index=False)

    metrics = {
        "SPF present": m.spf_present,
        "SPF strict (-all / ~all)": m.spf_strict,
        "SPF >10 lookups (broken)": m.spf_lookups.fillna(0) > 10,
        "Multiple SPF records (broken)": m.spf_multiple,
        "DMARC present": m.dmarc_present,
        "DMARC enforced (quarantine/reject)": m.dmarc_enforced,
        "DMARC p=reject": m.dmarc_p.eq("reject"),
        "DKIM detected (lower bound)": m.dkim_found,
        "MTA-STS published": m.mta_sts_dns,
        "MTA-STS enforce": m.mta_sts_mode.eq("enforce"),
        "TLS-RPT": m.tls_rpt,
        "DNSSEC": m.dnssec,
        "BIMI": m.bimi,
        "Spoofable (no enforced DMARC)": m.spoofable,
    }
    overall = pd.Series({k: 100 * v.mean() for k, v in metrics.items()}, name="% of mail-enabled domains")

    by_sector = m.groupby("sector").agg(
        domains=("domain", "count"),
        dmarc_present=("dmarc_present", lambda s: 100 * s.mean()),
        dmarc_enforced=("dmarc_enforced", lambda s: 100 * s.mean()),
        spf_strict=("spf_strict", lambda s: 100 * s.mean()),
        dnssec=("dnssec", lambda s: 100 * s.mean()),
        mean_score=("score", "mean"),
    )
    by_sector = by_sector[by_sector.domains >= args.min_group].sort_values("mean_score", ascending=False)

    by_provider = m.groupby(m.provider.fillna("Unknown")).agg(
        domains=("domain", "count"),
        dmarc_enforced=("dmarc_enforced", lambda s: 100 * s.mean()),
        spf_strict=("spf_strict", lambda s: 100 * s.mean()),
        mean_score=("score", "mean"),
    )
    by_provider = by_provider[by_provider.domains >= args.min_group].sort_values("domains", ascending=False)

    with open("results/summary.md", "w") as f:
        f.write("# .ke Email Security - Summary\n\n")
        f.write(f"- Domains scanned: **{total}**\n- Resolving (alive): **{live}**\n")
        f.write(f"- Mail-enabled (valid MX): **{len(m)}**\n- Mean hardening score: **{m.score.mean():.1f}/100**\n\n")
        f.write("## Adoption (mail-enabled domains)\n\n" + md(overall.to_frame()) + "\n\n")
        f.write("## By sector\n\n" + md(by_sector) + "\n\n")
        f.write("## By mail provider\n\n" + md(by_provider) + "\n")

    # Charts
    overall.sort_values().plot.barh(figsize=(9, 6), color="#2b6cb0")
    plt.xlabel("% of mail-enabled .ke domains"); plt.title("Email security adoption across .ke")
    plt.tight_layout(); plt.savefig("results/adoption.png", dpi=160); plt.close()

    by_sector.dmarc_enforced.sort_values().plot.barh(figsize=(8, 4), color="#c53030")
    plt.xlabel("% with enforced DMARC"); plt.title("Enforced DMARC by sector")
    plt.tight_layout(); plt.savefig("results/dmarc_by_sector.png", dpi=160); plt.close()

    by_provider.dmarc_enforced.sort_values().plot.barh(figsize=(8, 5), color="#2f855a")
    plt.xlabel("% with enforced DMARC"); plt.title("Enforced DMARC by mail provider")
    plt.tight_layout(); plt.savefig("results/dmarc_by_provider.png", dpi=160); plt.close()

    m.score.plot.hist(bins=20, figsize=(8, 4), color="#6b46c1")
    plt.xlabel("Email hardening score"); plt.title("Score distribution")
    plt.tight_layout(); plt.savefig("results/score_hist.png", dpi=160); plt.close()
    print("Wrote results/summary.md and charts. Raw per-domain CSV is in data/ (gitignored).")


if __name__ == "__main__":
    main()
