# KE-MailShield: the state of email security across .ke

A reproducible, **passive**, public-data study of how Kenyan domains protect their email against spoofing and phishing: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI and DNSSEC.

> Headline question: **how many .ke domains that receive email can be spoofed today, and who is doing it right?**

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python collect_domains.py            # builds data/domains.txt from Certificate Transparency
python scan.py --workers 30          # DNS-only scan, resumable -> data/results.jsonl
python analyze.py                    # -> results/summary.md + charts
```
Optional: `--tranco top-1m.csv` for `collect_domains.py`; `--no-dkim` / `--no-http` for `scan.py`.

## Method
- **Domain list:** names from public CT logs (crt.sh) reduced to registrable domains under `co.ke, or.ke, go.ke, ac.ke, sc.ke, ne.ke, me.ke, info.ke, mobi.ke, .ke`. KENIC does not publish the zone, so this is a sample biased toward HTTPS sites.
- **Scan:** DNS queries via public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) plus one HTTPS GET of the public MTA-STS policy file when published. **No SMTP connections, no port scans.**
- **Population:** domains with a valid, non-null MX ("mail-enabled").
- **Score (0-100):** SPF 20/15/5 for `-all`/`~all`/other + 5 for valid (<=10 lookups, single record); DMARC 10/25/35 for none/quarantine/reject + 5 for `rua`; DKIM detected 10; MTA-STS enforce 10 / testing 5; TLS-RPT 5; DNSSEC 10.
- **Spoofable:** mail-enabled domain without enforced DMARC (`quarantine`/`reject`).

## Limitations (state these in your report)
- DKIM selectors can't be enumerated: detection is a **lower bound**.
- Domains without MX can still receive mail via implicit A-record fallback; they're excluded.
- CT sampling bias; the scan is a point-in-time snapshot; third-party senders/subdomains aren't assessed.
- `pct<100` DMARC and `sp=` subdomain policy are recorded but not scored.

## Ethics & responsible use
- Only public DNS data and one public policy file; low request rate; identifiable UA string.
- **Publish aggregates, not a per-domain "shame list".** Raw data is gitignored.
- Share notable findings (e.g. unprotected government domains) privately with the National KE-CIRT/CC before publication, and give a reasonable disclosure window.

## Make it stand out
1. Write it up as a report/blog: headline numbers, sector ranking, provider effect (do Google/Microsoft tenants do better?), the "p=none plateau", broken SPF (>10 lookups).
2. Re-scan monthly and publish the trend line (longitudinal data is rare and valuable).
3. Add a small "check your domain" CLI using `scan.scan("example.co.ke")` and a fix-it guide for Kenyan SMEs.
4. Compare against global DMARC adoption figures with sources cited.
5. Share on LinkedIn/X, submit to local security meetups and conferences.

MIT licensed.
