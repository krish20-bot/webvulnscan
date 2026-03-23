"""HTML Report Generator — generates a styled, self-contained HTML report."""
import html
from datetime import datetime

def generate_html_report(results: dict) -> str:
    findings = results.get("findings", [])
    target = results.get("target", "Unknown")
    scan_start = results.get("scan_start", "")
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] += 1
    risk_score = min(100, counts["HIGH"]*25 + counts["MEDIUM"]*10 + counts["LOW"]*3)
    if risk_score >= 75: risk_label, risk_color = "CRITICAL", "#ff2a6d"
    elif risk_score >= 50: risk_label, risk_color = "HIGH", "#ff6b35"
    elif risk_score >= 25: risk_label, risk_color = "MEDIUM", "#ffb627"
    elif risk_score > 0: risk_label, risk_color = "LOW", "#05d9e8"
    else: risk_label, risk_color = "NONE", "#01ffc3"
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 4))
    finding_cards = ""
    for f in sorted_findings:
        sev = f["severity"]
        sc = {"HIGH":"#ff2a6d","MEDIUM":"#ffb627","LOW":"#05d9e8","INFO":"#7a7d85"}
        c = sc.get(sev, "#7a7d85")
        ev = f'<div class="finding-detail"><span class="detail-label">Evidence</span><pre class="evidence-box">{html.escape(str(f.get("evidence","")))}</pre></div>' if f.get("evidence") else ""
        rm = f'<div class="finding-detail"><span class="detail-label">Remediation</span><p class="remediation-text">{html.escape(str(f.get("remediation","")))}</p></div>' if f.get("remediation") else ""
        finding_cards += f'<div class="finding-card" style="--accent:{c};" onclick="this.classList.toggle(\'expanded\')"><div class="finding-header"><span class="severity-badge" style="background:{c};">{sev}</span><span class="finding-title">{html.escape(str(f.get("title","")))}</span><span class="scanner-tag">{html.escape(str(f.get("scanner","")))}</span><span class="expand-icon">&#9662;</span></div><div class="finding-body"><p class="finding-desc">{html.escape(str(f.get("description","")))}</p>{ev}{rm}</div></div>'
    bars = ""
    for sev, c in [("HIGH","#ff2a6d"),("MEDIUM","#ffb627"),("LOW","#05d9e8"),("INFO","#7a7d85")]:
        pct = (counts[sev]/max(len(findings),1))*100
        bars += f'<div class="severity-row"><span class="sev-label" style="color:{c};">{sev}</span><div class="sev-bar-track"><div class="sev-bar-fill" style="width:{pct}%;background:{c};"></div></div><span class="sev-count" style="color:{c};">{counts[sev]}</span></div>'
    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>WebVulnScan Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0a0e17;--bg2:#111827;--card:#151c2c;--border:#1e293b;--t1:#e2e8f0;--t2:#94a3b8;--t3:#64748b;--cyan:#05d9e8;--green:#01ffc3;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--t1);line-height:1.6;}}
.container{{max-width:960px;margin:0 auto;padding:40px 24px;}}
.report-header{{text-align:center;margin-bottom:48px;padding-bottom:32px;border-bottom:1px solid var(--border);}}
.report-header h1{{font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:var(--cyan);margin-bottom:16px;}}
.target-url{{font-family:'JetBrains Mono',monospace;font-size:.95rem;color:var(--t2);background:var(--bg2);padding:10px 20px;border-radius:6px;border:1px solid var(--border);display:inline-block;margin-bottom:12px;word-break:break-all;}}
.scan-meta{{font-size:.8rem;color:var(--t3);}}
.stats-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:40px;}}
@media(max-width:640px){{.stats-grid{{grid-template-columns:1fr;}}}}
.gauge-card,.breakdown-card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:32px;}}
.gauge-card{{text-align:center;box-shadow:0 0 30px rgba(5,217,232,.15);}}
.gauge-card h2,.breakdown-card h2{{font-size:.75rem;text-transform:uppercase;letter-spacing:2px;color:var(--t3);margin-bottom:24px;}}
.gauge-score{{font-family:'JetBrains Mono',monospace;font-size:3.5rem;font-weight:700;color:{risk_color};}}
.risk-label{{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:700;color:{risk_color};letter-spacing:3px;margin-top:8px;}}
.severity-row{{display:flex;align-items:center;margin-bottom:16px;}}
.sev-label{{font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600;width:72px;flex-shrink:0;}}
.sev-bar-track{{flex:1;height:28px;background:var(--bg2);border-radius:6px;margin:0 12px;overflow:hidden;}}
.sev-bar-fill{{height:100%;border-radius:6px;animation:grow 1s ease-out;}}
@keyframes grow{{from{{width:0;}}}}
.sev-count{{font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;width:30px;text-align:right;}}
.findings-section h2{{font-size:.75rem;text-transform:uppercase;letter-spacing:2px;color:var(--t3);margin-bottom:16px;}}
.finding-card{{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;margin-bottom:8px;cursor:pointer;transition:background .2s;}}
.finding-card:hover{{background:#1a2236;}}
.finding-header{{display:flex;align-items:center;padding:14px 18px;gap:12px;}}
.severity-badge{{font-family:'JetBrains Mono',monospace;font-size:.65rem;font-weight:700;padding:3px 8px;border-radius:4px;color:var(--bg);letter-spacing:1px;flex-shrink:0;}}
.finding-title{{flex:1;font-weight:600;font-size:.95rem;}}
.scanner-tag{{font-size:.7rem;color:var(--t3);background:var(--bg2);padding:2px 8px;border-radius:4px;flex-shrink:0;}}
.expand-icon{{color:var(--t3);transition:transform .3s;}}
.finding-card.expanded .expand-icon{{transform:rotate(180deg);}}
.finding-body{{max-height:0;overflow:hidden;transition:max-height .4s ease,padding .3s;padding:0 18px;}}
.finding-card.expanded .finding-body{{max-height:500px;padding:0 18px 18px;}}
.finding-desc{{color:var(--t2);font-size:.9rem;margin-bottom:12px;}}
.detail-label{{font-family:'JetBrains Mono',monospace;font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--t3);display:block;margin-bottom:4px;}}
.evidence-box{{font-family:'JetBrains Mono',monospace;font-size:.8rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;color:var(--cyan);white-space:pre-wrap;word-break:break-all;}}
.remediation-text{{font-size:.85rem;color:var(--green);background:rgba(1,255,195,.05);border:1px solid rgba(1,255,195,.15);border-radius:6px;padding:10px 14px;}}
.finding-detail{{margin-bottom:10px;}}
.report-footer{{text-align:center;padding-top:32px;border-top:1px solid var(--border);color:var(--t3);font-size:.8rem;}}
.report-footer a{{color:var(--cyan);text-decoration:none;}}
@media print{{body{{background:#fff;color:#111;}}.finding-body{{max-height:none!important;padding:0 18px 18px!important;}}}}
</style></head><body><div class="container">
<div class="report-header"><h1>&#x1f6e1; WebVulnScan Report</h1><div class="target-url">{html.escape(target)}</div><div class="scan-meta">Scanned {scan_start[:19].replace("T"," ") if scan_start else "N/A"} &bull; {len(findings)} findings</div></div>
<div class="stats-grid"><div class="gauge-card"><h2>Risk Score</h2><div class="gauge-score">{risk_score}</div><div class="risk-label">{risk_label}</div></div><div class="breakdown-card"><h2>Severity Breakdown</h2>{bars}</div></div>
<div class="findings-section"><h2>Findings ({len(findings)})</h2>{finding_cards}</div>
<div class="report-footer">Generated by <a href="https://github.com/krish20-bot/webvulnscan">WebVulnScan</a> &bull; {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
</div></body></html>'''
