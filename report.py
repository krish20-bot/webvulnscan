from datetime import datetime

def generate_report(results):
    findings = results.get("findings", [])
    sc = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sc[f.get("severity", "INFO")] = sc.get(f.get("severity", "INFO"), 0) + 1
    score = min(100, sc["HIGH"]*25 + sc["MEDIUM"]*10 + sc["LOW"]*3)
    label = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW" if score > 0 else "NONE"
    return {
        "metadata": {"generated": datetime.now().isoformat(), "target": results["target"]},
        "summary": {"total": len(findings), "breakdown": sc, "risk_score": score, "risk_label": label},
        "findings": sorted(findings, key=lambda f: {"HIGH":0,"MEDIUM":1,"LOW":2,"INFO":3}.get(f["severity"],4)),
    }
