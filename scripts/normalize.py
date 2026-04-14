#!/usr/bin/env python3
"""
normalize.py — Phase 5: Normaliza, deduplica, classifica e enriquece todos os achados.
Uso: python3 scripts/normalize.py
     Espera que os artifacts das fases 1-4 estejam em all/phase{1,2,3,4}/
     Gera: output/normalized-findings.json
"""
import json, glob, os, hashlib
from datetime import datetime, timezone

def read_lines(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except:
        return []

def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return default if default is not None else {}

def main():
    domain        = os.environ.get("DOMAIN", "")
    main_ip       = os.environ.get("MAIN_IP", "")
    asn           = os.environ.get("ASN", "")
    org           = os.environ.get("ORG", "")
    registrar     = os.environ.get("REGISTRAR", "")
    tech_hint     = os.environ.get("TECH_HINT", "")
    scan_id       = os.environ.get("SCAN_ID", "")
    scan_ts       = datetime.now(timezone.utc).isoformat()

    print("[*] Starting data normalization...")

    # ── Subdomains ────────────────────────────────────────────────────────────
    subdomains = set()
    for p in glob.glob("all/phase1/subdomains.txt"):
        for line in read_lines(p):
            subdomains.add(line)
    print(f"    Subdomains: {len(subdomains)}")

    # ── Live Hosts ────────────────────────────────────────────────────────────
    live_hosts, seen_urls = [], set()
    for p in glob.glob("all/phase3/active/live.json"):
        for line in read_lines(p):
            try:
                h = json.loads(line)
                url = h.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    live_hosts.append({
                        "url":    url,
                        "status": h.get("status_code"),
                        "title":  h.get("title", ""),
                        "server": h.get("webserver", ""),
                        "tech":   h.get("tech", []),
                    })
            except:
                pass
    print(f"    Live hosts: {len(live_hosts)}")

    # ── Vuln Findings (Nuclei) ────────────────────────────────────────────────
    vuln_findings, seen_hashes = [], set()

    def add_finding(item):
        key = hashlib.md5(
            f"{item.get('template-id','')}{item.get('matched-at','')}".encode()
        ).hexdigest()
        if key in seen_hashes:
            return
        seen_hashes.add(key)
        info = item.get("info", {})
        vuln_findings.append({
            "id":          item.get("template-id", ""),
            "name":        info.get("name", ""),
            "severity":    info.get("severity", "info"),
            "host":        item.get("host", ""),
            "url":         item.get("matched-at", ""),
            "tags":        info.get("tags", []),
            "description": info.get("description", ""),
            "cvss_score":  info.get("classification", {}).get("cvss-score", ""),
            "cve":         info.get("classification", {}).get("cve-id", ""),
            "extracted":   item.get("extracted-results", []),
        })

    # Phase 4 (main vuln scan)
    d = read_json("all/phase4/all_findings.json")
    for item in d.get("findings", []):
        add_finding(item)

    # Phase 2 OSINT Nuclei
    for p in glob.glob("all/phase2/nuclei_osint/*.jsonl"):
        for line in read_lines(p):
            try:
                add_finding(json.loads(line))
            except:
                pass

    print(f"    Vuln findings: {len(vuln_findings)}")

    # ── URLs, Params, Endpoints ───────────────────────────────────────────────
    params        = read_lines("all/phase1/params_get.txt")[:300]
    juicy_urls    = read_lines("all/phase1/urls_juicy.txt")[:100]
    api_endpoints = read_lines("all/phase1/api_endpoints.txt")[:100]
    post_endpoints= read_lines("all/phase1/post_endpoints.txt")[:50]

    # ── OSINT Data ────────────────────────────────────────────────────────────
    dorks_data  = read_json("all/phase2/dorks/dorks_structured.json")
    github_data = read_json("all/phase2/dorks/github_findings.json")
    shodan_data = read_json("all/phase2/osint/shodan.json")
    js_data     = read_json("all/phase3/js/js_analysis.json")
    ffuf_data   = read_json("all/phase3/dirs/ffuf_consolidated.json")
    email_sec   = "\n".join(read_lines("all/phase1/email_security.txt"))

    # ── Classify by Type ─────────────────────────────────────────────────────
    def has_tag(v, tags):
        return any(t in (v.get("tags") or []) for t in tags)

    classified = {
        "exposure":         [v for v in vuln_findings if has_tag(v, ["exposure","config","misconfig"])],
        "admin_panels":     [v for v in vuln_findings if has_tag(v, ["admin","panel","login","dashboard"])],
        "cves":             [v for v in vuln_findings if v.get("cve")],
        "default_creds":    [v for v in vuln_findings if has_tag(v, ["default-login","default-credentials"])],
        "info_disclosure":  [v for v in vuln_findings if has_tag(v, ["disclosure","info","debug"])],
        "injection":        [v for v in vuln_findings if has_tag(v, ["sqli","xss","rce","ssti","xxe","lfi","ssrf"])],
        "misconfiguration": [v for v in vuln_findings if has_tag(v, ["misconfiguration","headers","cors"])],
    }

    by_severity = {}
    for v in vuln_findings:
        by_severity.setdefault(v.get("severity","info"), []).append(v)

    # ── Build normalized-findings.json ───────────────────────────────────────
    normalized = {
        "meta": {
            "scan_id":       scan_id,
            "timestamp":     scan_ts,
            "domain":        domain,
            "main_ip":       main_ip,
            "asn":           asn,
            "org":           org,
            "registrar":     registrar,
            "server_tech":   tech_hint,
            "scan_mode":     os.environ.get("SCAN_MODE", ""),
            "stealth_level": os.environ.get("STEALTH_LEVEL", ""),
        },
        "summary": {
            "subdomains_total": len(subdomains),
            "live_hosts":       len(live_hosts),
            "vulns_critical":   len(by_severity.get("critical", [])),
            "vulns_high":       len(by_severity.get("high", [])),
            "vulns_medium":     len(by_severity.get("medium", [])),
            "vulns_low":        len(by_severity.get("low", [])),
            "vulns_info":       len(by_severity.get("info", [])),
            "params_found":     len(params),
            "juicy_urls":       len(juicy_urls),
            "api_endpoints":    len(api_endpoints),
            "github_leaks":     github_data.get("total", 0),
            "js_secrets":       js_data.get("total_findings", 0),
            "shodan_hosts":     len(shodan_data.get("domain_results", [])),
            "exposed_cves":     len(shodan_data.get("cves", [])),
            "dirs_found":       ffuf_data.get("total", 0),
        },
        "phase1_passive": {
            "subdomains":    sorted(list(subdomains))[:500],
            "email_security": email_sec,
            "params":        params,
            "api_endpoints": api_endpoints,
            "post_endpoints":post_endpoints,
            "juicy_urls":    juicy_urls,
        },
        "phase2_osint": {
            "dorks":        dorks_data,
            "github_leaks": github_data,
            "shodan":       shodan_data,
        },
        "phase3_active": {
            "live_hosts":  live_hosts[:200],
            "js_analysis": js_data,
            "dirs_found":  ffuf_data,
        },
        "phase4_vulns": {
            "by_severity":  by_severity,
            "classified":   {k: len(v) for k, v in classified.items()},
            "all_findings": vuln_findings[:500],
        },
    }

    os.makedirs("output", exist_ok=True)
    with open("output/normalized-findings.json", "w") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    s = normalized["summary"]
    print(f"""
[+] Normalized findings saved to output/normalized-findings.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Subdomains:    {s['subdomains_total']}
  Live Hosts:    {s['live_hosts']}
  Critical:      {s['vulns_critical']}
  High:          {s['vulns_high']}
  Medium:        {s['vulns_medium']}
  Low:           {s['vulns_low']}
  GitHub Leaks:  {s['github_leaks']}
  JS Secrets:    {s['js_secrets']}
  Dirs Found:    {s['dirs_found']}
""")

if __name__ == "__main__":
    main()
