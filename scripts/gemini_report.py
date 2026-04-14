#!/usr/bin/env python3
"""
gemini_report.py — Gera relatório de correlação AI usando Gemini 2.0 Flash.

Uso:
    export GEMINI_API_KEY="sua-chave"
    python3 scripts/gemini_report.py normalized-findings.json [domain] [scan_id]

O relatório é salvo em output/report/RECON-REPORT.md
"""
import json, os, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
MODEL      = "gemini-2.0-flash"
API_URL    = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={GEMINI_KEY}"
SEV_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


# ─────────────────────────────────────────────────────────────────────────────
# GEMINI HELPER
# ─────────────────────────────────────────────────────────────────────────────
def gemini(prompt: str, max_tokens: int = 4096, label: str = "") -> str:
    if not GEMINI_KEY:
        return (
            "⚠️  GEMINI_API_KEY não configurado.\n"
            "    export GEMINI_API_KEY='sua-chave'\n"
            "    Obtenha em: https://aistudio.google.com/app/apikey"
        )

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.3},
    }).encode()

    req = urllib.request.Request(
        API_URL, data=body, headers={"Content-Type": "application/json"}
    )

    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                r = json.loads(resp.read())
                text = r["candidates"][0]["content"]["parts"][0]["text"]
                if label:
                    print(f"    ✅  {label} ({len(text):,} chars)")
                return text
        except urllib.error.HTTPError as e:
            err = e.read().decode()
            if e.code == 429:
                wait = 30 * (attempt + 1)
                print(f"    ⏳  Rate limit — aguardando {wait}s...")
                time.sleep(wait)
            else:
                return f"Gemini API error {e.code}: {err[:300]}"
        except Exception as e:
            print(f"    ⚠️  Tentativa {attempt+1}/4 falhou: {e}")
            time.sleep(15)

    return "Gemini não respondeu após 4 tentativas."


# ─────────────────────────────────────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────────────────────────────────────
def prompt_attack_chains(domain: str, ctx_json: str) -> str:
    return f"""
Você é um pentester sênior e especialista em OSINT. Analise os resultados do recon abaixo
e produza uma análise técnica profunda de correlação de dados e vetores de ataque.

## DADOS DO RECON — {domain}
```json
{ctx_json}
```

## TAREFA: CORRELAÇÃO & ATTACK CHAINS

### 🔗 1. CORRELAÇÃO DE DADOS
Explique como os achados se conectam entre si para formar ameaças compostas.
Seja específico com os dados encontrados. Exemplos de correlações:
- Subdomínio + painel admin + tecnologia desatualizada
- Arquivo .env exposto + credenciais no GitHub = acesso direto
- Endpoint de API + parâmetros do Wayback = possível SQLi/IDOR
- SPF/DMARC ausente + emails coletados = risco de email spoofing
- CVEs Shodan + versão de servidor + exploit público disponível
- JS com secrets + endpoints internos = acesso à infraestrutura

### ⛓️ 2. TOP 5 ATTACK CHAINS
Para cada cadeia:
**Chain [N]: [Nome descritivo]**
- **Pré-requisitos**: O que o atacante precisa ter
- **Passo a passo**: Numerado e técnico
- **Ferramentas**: sqlmap, metasploit, hydra, burp, etc.
- **Impacto**: O que pode ser comprometido
- **Probabilidade**: Alta/Média/Baixa com justificativa

### 🗺️ 3. MAPA DE SUPERFÍCIE DE ATAQUE
| Ponto de Entrada | Tipo | Risco | Condição |
|---|---|---|---|

### 🛡️ 4. TOP 10 REMEDIAÇÕES PRIORITÁRIAS
Ordenadas por urgência. Inclua dificuldade de implementação.

Use SOMENTE os dados fornecidos. Seja técnico e específico.
"""


def prompt_exec_summary(domain: str, meta: dict, summary: dict,
                         shodan_cves: list, email_sec: str) -> str:
    return f"""
Você é um consultor de segurança sênior escrevendo para o CISO/CTO de uma empresa.

## CONTEXTO — {domain}
- IP: {meta.get('main_ip','')} | ASN: {meta.get('asn','')} | Org: {meta.get('org','')}
- Tecnologia: {meta.get('server_tech','')}
- Subdomínios: {summary.get('subdomains_total',0)} | Hosts ativos: {summary.get('live_hosts',0)}
- Críticas: {summary.get('vulns_critical',0)} | Altas: {summary.get('vulns_high',0)}
- GitHub leaks: {summary.get('github_leaks',0)} | JS secrets: {summary.get('js_secrets',0)}
- CVEs Shodan: {shodan_cves[:5]}
- Email security: {email_sec[:400]}

## TAREFA: EXECUTIVE SUMMARY (em português, linguagem executiva)

**🎯 NÍVEL DE RISCO GERAL**: [Crítico/Alto/Médio/Baixo] — Score X/10
(justificativa em 2-3 linhas)

**📌 PRINCIPAIS DESCOBERTAS** (máximo 5 bullets, foco no impacto de negócio):

**💼 IMPACTO POTENCIAL NO NEGÓCIO**:
Vazamento de dados, downtime, comprometimento de clientes, LGPD, reputação.

**📧 POSTURA DE EMAIL (SPF/DMARC/DKIM)**:
Risco de phishing e spoofing.

**⚡ 3 AÇÕES IMEDIATAS (próximas 72h)**:

**📅 CRONOGRAMA DE REMEDIAÇÃO**:
- Curto prazo (1-7 dias):
- Médio prazo (1-4 semanas):
- Longo prazo (1-3 meses):
"""


def prompt_threat_intel(domain: str, meta: dict, shodan_cves: list,
                         critical_vulns: list, subs_sample: list,
                         api_eps: list, post_eps: list,
                         github_items: list, js_findings: list) -> str:
    return f"""
Você é um analista de Threat Intelligence com foco em segurança ofensiva.

## ALVO: {domain}
- Tech stack: {meta.get('server_tech','unknown')}
- CVEs expostos: {json.dumps(shodan_cves[:15])}
- Vulns críticas: {json.dumps([v.get('name','') for v in critical_vulns])}
- Subdomínios notáveis: {json.dumps(subs_sample[:20])}
- APIs: {json.dumps(api_eps[:15])}
- POST endpoints: {json.dumps(post_eps[:10])}
- GitHub leaks: {json.dumps([i.get('file','') for i in github_items[:8]])}
- JS secrets: {json.dumps([f.get('type','') for f in js_findings[:8]])}

## TAREFA: THREAT INTELLIGENCE REPORT

### 🏢 PERFIL DE INFRAESTRUTURA INFERIDA
Stack tecnológica provável, maturidade de segurança, tipo de aplicação.

### 💀 ANÁLISE DE CVEs E VULNERABILIDADES
Para cada CVE/vuln encontrada:
- O que permite explorar
- Exploit público disponível? (Metasploit module, PoC GitHub, etc.)
- Dificuldade de exploração: 1 (trivial) a 5 (complexo)

### 🚪 VETORES DE ACESSO EXTERNO
**Anônimo (sem credenciais):**
**Pós-phishing (usuário comprometido):**
**Via supply chain (CI/CD, dependências):**

### 🔍 INDICADORES DE COMPROMETIMENTO POTENCIAL
Sinais que indicam o alvo pode JÁ estar comprometido.

### 🎣 TOP 10 DORKS PRIORITÁRIOS
Para investigação manual baseada na tech stack detectada.
"""


# ─────────────────────────────────────────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────────────────────────────────────────
def build_report(domain: str, scan_id: str, ts: str,
                 data: dict, attack_chains: str,
                 exec_summary: str, threat_intel: str) -> str:

    meta    = data.get("meta", {})
    summary = data.get("summary", {})
    p1      = data.get("phase1_passive", {})
    p2      = data.get("phase2_osint", {})
    p3      = data.get("phase3_active", {})
    p4      = data.get("phase4_vulns", {})

    by_severity  = p4.get("by_severity", {})
    github_items = p2.get("github_leaks", {}).get("items", [])
    js_findings  = p3.get("js_analysis", {}).get("findings", [])
    dirs_found   = p3.get("dirs_found", {}).get("results", [])
    api_eps      = p1.get("api_endpoints", [])
    juicy        = p1.get("juicy_urls", [])
    shodan_cves  = p2.get("shodan", {}).get("cves", [])
    email_sec    = p1.get("email_security", "")
    subs_list    = p1.get("subdomains", [])
    dork_cats    = p2.get("dorks", {}).get("categories", {})
    all_dorks    = p2.get("dorks", {}).get("dorks", [])

    md = f"""# 🥷 Advanced OSINT & Recon Report — AI-Powered

> **Target:** `{domain}` &nbsp;|&nbsp; **Scan ID:** `{scan_id}` &nbsp;|&nbsp; **Generated:** {ts}
> **Mode:** {meta.get('scan_mode','')} &nbsp;|&nbsp; **Stealth:** {meta.get('stealth_level','')}

---

## 📋 Executive Summary

{exec_summary}

---

## 📊 Dashboard — Findings Overview

| Categoria | Valor |
|:---|:---|
| 🌐 Subdomínios Descobertos | **{summary.get('subdomains_total',0)}** |
| 🟢 Hosts Ativos | **{summary.get('live_hosts',0)}** |
| 🔴 Vulnerabilidades Críticas | **{summary.get('vulns_critical',0)}** |
| 🟠 Vulnerabilidades Altas | **{summary.get('vulns_high',0)}** |
| 🟡 Vulnerabilidades Médias | **{summary.get('vulns_medium',0)}** |
| 🔵 Vulnerabilidades Baixas | **{summary.get('vulns_low',0)}** |
| 🎣 Vazamentos GitHub | **{summary.get('github_leaks',0)}** |
| 🔑 Secrets em JavaScript | **{summary.get('js_secrets',0)}** |
| 🌍 Hosts no Shodan | **{summary.get('shodan_hosts',0)}** |
| 💀 CVEs Expostos | **{summary.get('exposed_cves',0)}** |
| 📎 Parâmetros GET/POST | **{summary.get('params_found',0)}** |
| 🔗 Endpoints de API | **{summary.get('api_endpoints',0)}** |
| 📁 URLs Sensíveis | **{summary.get('juicy_urls',0)}** |
| 📂 Diretórios Descobertos | **{summary.get('dirs_found',0)}** |

---

## 🎯 Target Intelligence

| Campo | Valor |
|:---|:---|
| Domínio | `{domain}` |
| IP Principal | `{meta.get('main_ip','')}` |
| ASN | `{meta.get('asn','')}` |
| Organização | `{meta.get('org','')}` |
| Registrar | `{meta.get('registrar','')}` |
| Tecnologia Detectada | `{meta.get('server_tech','')}` |

---

## 🔗 Correlação & Attack Chains

{attack_chains}

---

## 🕵️ Threat Intelligence

{threat_intel}

---

## 🚨 Vulnerabilidades por Severidade

"""

    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        e = SEV_EMOJI.get(sev, "⚪")
        md += f"\n### {e} {sev.upper()} — {len(items)} finding(s)\n\n"
        for v in items[:20]:
            cve_str = f" `{v.get('cve')}`" if v.get("cve") else ""
            md += f"#### {v.get('name','unknown')}{cve_str}\n"
            md += f"- **Host:** `{v.get('url', v.get('host',''))}`\n"
            if v.get("cvss_score"):
                md += f"- **CVSS:** {v['cvss_score']}\n"
            if v.get("description"):
                md += f"- **Descrição:** {v['description'][:250]}\n"
            if v.get("extracted"):
                md += f"- **Extraído:** `{str(v['extracted'])[:200]}`\n"
            md += "\n"

    if github_items:
        md += f"\n---\n\n## 🐙 GitHub Leaks — {len(github_items)} repositórios\n\n"
        for item in github_items[:25]:
            md += f"- **[{item.get('repo','')}]({item.get('url','')})**\n"
            md += f"  - Arquivo: `{item.get('file','')}`\n"
            md += f"  - Query: `{item.get('query','')}`\n\n"

    if js_findings:
        md += f"\n---\n\n## 🔑 Secrets em JavaScript — {len(js_findings)} achados\n\n"
        for f in js_findings[:20]:
            e = SEV_EMOJI.get(f.get("severity", "medium"), "⚪")
            md += f"- {e} **{f.get('type','')}** — `{f.get('url','')}`\n"
            if f.get("matches"):
                md += f"  - Sample: `{str(f['matches'][0])[:120]}`\n\n"

    if dirs_found:
        md += f"\n---\n\n## 📂 Diretórios Descobertos (ffuf) — {len(dirs_found)} paths\n\n"
        for d in dirs_found[:30]:
            md += f"- `[{d.get('status','')}]` {d.get('url','')}\n"

    if api_eps:
        md += f"\n---\n\n## 🔗 API Endpoints ({len(api_eps)})\n\n"
        for ep in api_eps[:30]:
            md += f"- `{ep}`\n"

    if juicy:
        md += f"\n---\n\n## 📁 URLs Sensíveis — Wayback/GAU ({len(juicy)})\n\n"
        for u in juicy[:25]:
            md += f"- `{u}`\n"

    if dork_cats:
        md += f"\n---\n\n## 🎣 Google Dorks Gerados\n\n"
        for cat, items in dork_cats.items():
            md += f"- **{cat.replace('_',' ').title()}**: {len(items)} dorks\n"
        if all_dorks:
            md += "\n<details><summary>📋 Ver todos os dorks</summary>\n\n```\n"
            md += "\n".join(all_dorks)
            md += "\n```\n</details>\n"

    if shodan_cves:
        md += f"\n---\n\n## 💀 CVEs Expostos via Shodan\n\n"
        for cve in shodan_cves[:20]:
            md += f"- [`{cve}`](https://nvd.nist.gov/vuln/detail/{cve})\n"

    if email_sec:
        md += f"\n---\n\n## 📧 Segurança de Email (SPF/DMARC/DKIM)\n\n```\n{email_sec[:1500]}\n```\n"

    if subs_list:
        md += f"\n---\n\n## 🌐 Subdomínios — {len(subs_list)} total\n\n"
        md += "<details><summary>📋 Ver lista completa</summary>\n\n```\n"
        md += "\n".join(subs_list[:200])
        md += "\n```\n</details>\n"

    md += f"""
---

## 📎 Artifacts Disponíveis

| Artifact | Conteúdo |
|:---|:---|
| `normalized-findings.json` | Todos os dados normalizados |
| `phase4-vuln/` | Raw Nuclei output por severidade |
| `phase2-osint/dorks/` | Dorks + GitHub findings |
| `phase1-wayback/` | URLs, params, juicy files |

---

*🤖 Gerado por OSINT Recon Framework v2.0 — Gemini {MODEL}*
*Scan ID: `{scan_id}` — {ts}*
"""
    return md


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else "normalized/normalized-findings.json"
    domain     = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("DOMAIN", "")
    scan_id    = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("SCAN_ID", "unknown")
    ts         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"[*] Loading {input_file}...")
    with open(input_file) as f:
        data = json.load(f)

    if not domain:
        domain = data.get("meta", {}).get("domain", "unknown")

    meta    = data.get("meta", {})
    summary = data.get("summary", {})
    p1      = data.get("phase1_passive", {})
    p2      = data.get("phase2_osint", {})
    p3      = data.get("phase3_active", {})
    p4      = data.get("phase4_vulns", {})

    critical_vulns = p4.get("by_severity", {}).get("critical", [])[:10]
    high_vulns     = p4.get("by_severity", {}).get("high", [])[:10]
    js_findings    = p3.get("js_analysis", {}).get("findings", [])[:8]
    github_items   = p2.get("github_leaks", {}).get("items", [])[:8]
    shodan_cves    = p2.get("shodan", {}).get("cves", [])
    api_eps        = p1.get("api_endpoints", [])[:20]
    post_eps       = p1.get("post_endpoints", [])[:15]
    juicy          = p1.get("juicy_urls", [])[:15]
    subs_sample    = p1.get("subdomains", [])[:30]
    email_sec      = p1.get("email_security", "")[:600]
    dirs_found     = p3.get("dirs_found", {}).get("results", [])[:20]
    dork_cats      = p2.get("dorks", {}).get("categories", {})
    live_sample    = p3.get("live_hosts", [])[:15]

    ctx = {
        "target": domain, "meta": meta, "summary": summary,
        "critical_vulns": critical_vulns, "high_vulns": high_vulns,
        "js_secrets": js_findings, "github_leaks": github_items,
        "live_hosts": live_sample, "shodan_cves": shodan_cves,
        "api_endpoints": api_eps, "post_endpoints": post_eps,
        "juicy_urls": juicy, "dirs_found": dirs_found,
        "email_security": email_sec, "subdomains_sample": subs_sample,
        "dork_categories": {k: len(v) for k, v in dork_cats.items()},
    }
    ctx_json = json.dumps(ctx, ensure_ascii=False)[:14000]

    print("[*] Calling Gemini API (3 prompts)...")

    print("  [1/3] Attack Chains & Correlation...")
    attack_chains = gemini(prompt_attack_chains(domain, ctx_json),
                           max_tokens=4096, label="Attack Chains")
    time.sleep(8)

    print("  [2/3] Executive Summary...")
    exec_summary = gemini(prompt_exec_summary(domain, meta, summary, shodan_cves, email_sec),
                          max_tokens=2048, label="Executive Summary")
    time.sleep(8)

    print("  [3/3] Threat Intelligence...")
    threat_intel = gemini(prompt_threat_intel(domain, meta, shodan_cves, critical_vulns,
                                               subs_sample, api_eps, post_eps,
                                               github_items, js_findings),
                          max_tokens=3000, label="Threat Intelligence")

    # ── Build & save report ───────────────────────────────────────────────────
    md = build_report(domain, scan_id, ts, data, attack_chains, exec_summary, threat_intel)

    output_dir = Path("output/report")
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "RECON-REPORT.md"
    ai_path     = output_dir / "ai_analysis.json"

    report_path.write_text(md, encoding="utf-8")
    ai_path.write_text(json.dumps({
        "scan_id":       scan_id,
        "domain":        domain,
        "timestamp":     ts,
        "model":         MODEL,
        "exec_summary":  exec_summary,
        "attack_chains": attack_chains,
        "threat_intel":  threat_intel,
        "summary":       summary,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"""
╔══════════════════════════════════════════════════╗
║  ✅  RELATÓRIO GERADO COM SUCESSO                ║
╚══════════════════════════════════════════════════╝
  📄  {report_path}  ({len(md)//1024} KB)
  🤖  {ai_path}
""")

if __name__ == "__main__":
    main()
