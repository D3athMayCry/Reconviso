#!/usr/bin/env python3
"""
js_analysis.py — Analisa arquivos JavaScript em busca de secrets e endpoints.
Uso: python3 scripts/js_analysis.py <domain> <output_file>
"""
import re, json, sys, urllib.request, urllib.error

PATTERNS = {
    "aws_access_key":  (r"AKIA[0-9A-Z]{16}",                                          "critical"),
    "aws_secret_key":  (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", "critical"),
    "google_api_key":  (r"AIza[0-9A-Za-z\-_]{35}",                                    "critical"),
    "github_token":    (r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",           "critical"),
    "stripe_key":      (r"sk_live_[0-9a-zA-Z]{24}",                                    "critical"),
    "private_key":     (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",            "critical"),
    "sendgrid_key":    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",               "high"),
    "slack_token":     (r"xox[baprs]-([0-9a-zA-Z]{10,48})",                           "high"),
    "api_key_generic": (r"(?i)(api[_-]?key|apikey)[\"\\s]*[:=][\"\\s]*([A-Za-z0-9\-_]{20,})", "high"),
    "password_in_js":  (r"(?i)(password|passwd|pwd)[\"\\s]*[:=][\"\\s]*[\"']([^\"']{6,})[\"']", "high"),
    "jwt_token":       (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",        "medium"),
    "bearer_token":    (r"(?i)bearer\s+([A-Za-z0-9\-_.]{20,})",                       "medium"),
    "firebase_url":    (r"https://[a-z0-9-]+\.firebaseio\.com",                       "medium"),
    "internal_ips":    (r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "low"),
}

def fetch(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", errors="ignore")

def main():
    domain     = sys.argv[1] if len(sys.argv) > 1 else ""
    output_file= sys.argv[2] if len(sys.argv) > 2 else "output/js/js_analysis.json"
    js_files, findings = [], []

    try:
        html = fetch(f"https://{domain}")
        for js in re.findall(r'src=["\x27]([^"\']+\.js[^"\']*)["\x27]', html):
            if js.startswith("http"):     js_files.append(js)
            elif js.startswith("//"):     js_files.append("https:" + js)
            elif js.startswith("/"):      js_files.append(f"https://{domain}{js}")
    except Exception as e:
        print(f"[WARN] HTML fetch failed: {e}")

    print(f"[*] Found {len(js_files)} JS files — analyzing...")

    for url in js_files[:25]:
        try:
            content = fetch(url)
            for name, (pattern, severity) in PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        "url":      url,
                        "type":     name,
                        "severity": severity,
                        "matches":  [str(m)[:100] for m in matches[:3]],
                    })
        except Exception as e:
            print(f"[WARN] {url}: {e}")

    result = {
        "total_js_files": len(js_files),
        "total_findings": len(findings),
        "findings":       findings,
        "js_urls":        js_files,
    }

    import os; os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    crit = [x for x in findings if x["severity"] == "critical"]
    print(f"[+] JS Analysis done: {len(js_files)} files | {len(findings)} findings | {len(crit)} critical")
    print(f"[+] Output: {output_file}")

if __name__ == "__main__":
    main()
