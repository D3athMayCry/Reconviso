#!/usr/bin/env python3
"""
github_dorks.py — Busca vazamentos no GitHub via Code Search API.
Uso: python3 scripts/github_dorks.py <domain> <output_file>
     GITHUB_TOKEN deve estar no ambiente.
"""
import json, os, sys, time, urllib.request, urllib.parse, urllib.error

def main():
    domain      = sys.argv[1] if len(sys.argv) > 1 else ""
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output/dorks/github_findings.json"
    token       = os.environ.get("GITHUB_TOKEN", "")

    queries = [
        f'"{domain}" password',
        f'"{domain}" secret OR token OR api_key',
        f'"@{domain}" password',
        f'"{domain}" DB_PASSWORD OR DATABASE_URL',
        f'"{domain}" PRIVATE_KEY OR private_key',
        f'"{domain}" smtp_password OR SENDGRID_KEY',
        f'"{domain}" AWS_ACCESS_KEY OR AWS_SECRET_ACCESS_KEY',
        f'"{domain}" STRIPE_KEY OR TWILIO_AUTH OR MAILGUN',
    ]

    headers = {
        "Authorization":        f"Bearer {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    results = []
    print(f"[*] Running {len(queries)} GitHub dork queries for {domain}...")

    for q in queries:
        try:
            enc = urllib.parse.quote(q)
            url = f"https://api.github.com/search/code?q={enc}&per_page=10"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                items = data.get("items", [])
                for item in items:
                    results.append({
                        "query": q,
                        "repo":  item.get("repository", {}).get("full_name", ""),
                        "file":  item.get("path", ""),
                        "url":   item.get("html_url", ""),
                        "score": item.get("score", 0),
                    })
                print(f"  [{len(items):2d} hits] {q[:60]}")
        except urllib.error.HTTPError as e:
            print(f"  [ERR] {e.code} — {q[:50]}")
        except Exception as e:
            print(f"  [ERR] {e}")
        time.sleep(5)

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump({"total": len(results), "items": results}, f, indent=2)

    print(f"[+] GitHub Dorks done: {len(results)} results → {output_file}")

if __name__ == "__main__":
    main()
