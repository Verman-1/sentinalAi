"""
Turns a list of annotated findings (from Harness.run_all_annotated)
into a JSON file and a human-readable Markdown summary - the Markdown
version is meant to be screenshotted straight into a presentation.
"""

import json
from datetime import datetime, timezone


def write_json(findings: list[dict], path: str) -> None:
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)


def to_markdown(findings: list[dict], model_label: str) -> str:
    n_total = len(findings)
    n_success = sum(1 for f in findings if f["success"])
    lines = [
        f"# SentinelAI Harness Report",
        f"",
        f"**Target model:** {model_label}  ",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Attacks run:** {n_total}  |  **Vulnerabilities confirmed:** {n_success}",
        f"",
        f"| Attack | Result | Evidence |",
        f"|---|---|---|",
    ]
    for f in findings:
        result = "\U0001F534 VULNERABLE" if f["success"] else "\U0001F7E2 Not triggered"
        lines.append(f"| {f['attack_name']} | {result} | {f['evidence']} |")

    lines.append("")
    for f in findings:
        if not f["success"]:
            continue
        tax = f.get("taxonomy", {})
        mits = f.get("recommended_mitigations", [])
        lines.append(f"## {f['attack_name']}")
        lines.append(f"- **OWASP LLM Top 10:** {tax.get('owasp_llm_top10', 'n/a')}")
        lines.append(f"- **MITRE ATLAS:** {tax.get('mitre_atlas', 'n/a')}")
        lines.append(f"- **Evidence:** {f['evidence']}")
        if mits:
            lines.append(f"- **Recommended mitigations:**")
            for m in mits:
                lines.append(f"  - {m}")
        lines.append("")

    return "\n".join(lines)


def write_markdown(findings: list[dict], model_label: str, path: str) -> None:
    with open(path, "w") as f:
        f.write(to_markdown(findings, model_label))
