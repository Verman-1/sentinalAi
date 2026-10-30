"""
Turns a list of annotated findings (from Harness.run_all_annotated)
into a JSON file and a human-readable Markdown summary - the Markdown
version is meant to be screenshotted straight into a presentation.
Multi-model benchmark reports live in bench_report.py.
"""

import json
from datetime import datetime, timezone

SEVERITY_ICON = {
    "Critical": "\U0001F534",
    "High": "\U0001F7E0",
    "Medium": "\U0001F7E1",
    "Low": "\U0001F535",
    "None": "\U0001F7E2",
}


def _cell(text, limit: int = 180) -> str:
    """Make arbitrary model output safe inside a Markdown table cell."""
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def write_json(findings: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)


def to_markdown(findings: list[dict], model_label: str) -> str:
    n_total = len(findings)
    n_success = sum(1 for f in findings if f["success"])
    scored = [f for f in findings if f.get("risk_score") is not None]
    worst = max(scored, key=lambda f: f["risk_score"]) if scored else None
    lines = [
        "# SentinelAI Harness Report",
        "",
        f"**Target model:** {model_label}  ",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Attacks run:** {n_total}  |  **Vulnerabilities confirmed:** {n_success}"
        + (f"  |  **Highest risk:** {worst['risk_score']:.1f} ({worst['severity']})" if worst else ""),
        "",
        "| Attack | Result | Risk (0-100) | Probe success rate | Evidence |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        result = "\U0001F534 VULNERABLE" if f["success"] else "\U0001F7E2 Not triggered"
        if f.get("risk_score") is not None:
            risk = f"{SEVERITY_ICON.get(f['severity'], '')} {f['risk_score']:.1f} {f['severity']}"
            rate = f"{f.get('attack_success_rate', 0):.0%}"
        else:
            risk, rate = "n/a", "n/a"
        lines.append(f"| {f['attack_name']} | {result} | {risk} | {rate} | {_cell(f['evidence'])} |")

    lines.append("")
    for f in findings:
        if not f["success"]:
            continue
        tax = f.get("taxonomy", {})
        mits = f.get("recommended_mitigations", [])
        lines.append(f"## {f['attack_name']}")
        lines.append(f"- **OWASP LLM Top 10:** {tax.get('owasp_llm_top10', 'n/a')}")
        lines.append(f"- **MITRE ATLAS:** {tax.get('mitre_atlas', 'n/a')}")
        if f.get("risk_score") is not None:
            mean_factors = (f.get("risk_factors") or {}).get("mean_factors", {})
            factor_text = ", ".join(f"{k.replace('_', ' ')} {v:.2f}" for k, v in mean_factors.items())
            lines.append(f"- **Risk:** {f['risk_score']:.1f} ({f['severity']}) - mean factors: {factor_text}")
        lines.append(f"- **Evidence:** {_cell(f['evidence'], 400)}")
        if mits:
            lines.append("- **Recommended mitigations:**")
            for m in mits:
                lines.append(f"  - {m}")
        probes = f.get("probes") or []
        if probes:
            lines += ["", "| Probe | Family | Result | Risk |", "|---|---|---|---|"]
            for p in probes:
                risk = p.get("risk") or {}
                outcome = "succeeded" if p["success"] else "resisted"
                lines.append(
                    f"| {p['probe_id']} | {p['family']} | {outcome} | "
                    f"{risk.get('score', 0):.1f} {risk.get('severity', '')} |"
                )
        lines.append("")

    return "\n".join(lines)


def write_markdown(findings: list[dict], model_label: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_markdown(findings, model_label))
