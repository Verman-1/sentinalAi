"""
Human-validation tooling (synopsis Section 4, step iv).

  1. export     Draw a stratified, shuffled sample of scored probes from a
                benchmark's records.jsonl into a BLIND labelling sheet (no
                automated scores visible to annotators) plus a separate
                key file that holds the automated verdicts.
  2. label      Two annotators fill in the sheet independently:
                label_success (0/1) and label_severity (0 None, 1 Low,
                2 Medium, 3 High, 4 Critical).
  3. agreement  Inter-annotator agreement (Cohen's kappa; quadratic-
                weighted kappa for severity), then human consensus vs. the
                automated detector (kappa, precision/recall) and vs. the
                risk score (Spearman's rho).

    python -m sentinelai_harness.validation export --records results/x/records.jsonl --out labels/sheet.csv --n 60
    python -m sentinelai_harness.validation agreement --a labels/aman.csv --b labels/aditi.csv --key labels/sheet_key.csv

All statistics are implemented here without third-party dependencies and
are unit-tested against textbook values.
"""

import argparse
import csv
import json
import os
import random
from collections import Counter
from statistics import fmean

SEVERITY_LEVELS = ("None", "Low", "Medium", "High", "Critical")

SHEET_FIELDS = ["sample_id", "vulnerability_class", "attack", "objective", "prompt", "assistant_reply",
                "label_success", "label_severity", "notes"]
KEY_FIELDS = ["sample_id", "target", "config", "trial", "attack_id", "probe_id",
              "auto_success", "auto_risk", "auto_severity", "ground_truth"]


# ------------------------------------------------------------ statistics

def cohen_kappa(a, b) -> float | None:
    """Cohen's kappa for two raters' nominal labels. None when undefined
    (both raters used one identical category throughout)."""
    if len(a) != len(b) or not a:
        raise ValueError("label lists must be non-empty and of equal length")
    n = len(a)
    p_o = sum(x == y for x, y in zip(a, b)) / n
    count_a, count_b = Counter(a), Counter(b)
    p_e = sum(count_a[c] * count_b[c] for c in set(a) | set(b)) / (n * n)
    if p_e == 1.0:
        return None
    return (p_o - p_e) / (1 - p_e)


def weighted_kappa(a, b, k: int | None = None, weighting: str = "quadratic") -> float | None:
    """Cohen's weighted kappa for ordinal labels 0..k-1 (linear or quadratic weights)."""
    a = [int(x) for x in a]
    b = [int(y) for y in b]
    if len(a) != len(b) or not a:
        raise ValueError("label lists must be non-empty and of equal length")
    k = k or max(a + b) + 1
    if k < 2:
        return None
    n = len(a)
    observed = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        observed[x][y] += 1
    rows = [sum(observed[i]) for i in range(k)]
    cols = [sum(observed[i][j] for i in range(k)) for j in range(k)]

    def weight(i, j):
        d = abs(i - j) / (k - 1)
        return d * d if weighting == "quadratic" else d

    disagreement = sum(weight(i, j) * observed[i][j] for i in range(k) for j in range(k)) / n
    expected = sum(weight(i, j) * rows[i] * cols[j] for i in range(k) for j in range(k)) / (n * n)
    if expected == 0:
        return None
    return 1 - disagreement / expected


def _ranks(values) -> list:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for m in range(i, j + 1):
            ranks[order[m]] = (i + j) / 2 + 1  # average rank for ties
        i = j + 1
    return ranks


def spearman(x, y) -> float | None:
    """Spearman's rank correlation (ties get average ranks)."""
    if len(x) != len(y) or len(x) < 3:
        return None
    rx, ry = _ranks(list(x)), _ranks(list(y))
    mx, my = fmean(rx), fmean(ry)
    cov = sum((p - mx) * (q - my) for p, q in zip(rx, ry))
    var_x = sum((p - mx) ** 2 for p in rx)
    var_y = sum((q - my) ** 2 for q in ry)
    if var_x == 0 or var_y == 0:
        return None
    return cov / (var_x * var_y) ** 0.5


def interpret_kappa(kappa: float | None) -> str:
    """Landis & Koch (1977) verbal bands."""
    if kappa is None:
        return "undefined"
    if kappa < 0:
        return "poor"
    for upper, label in ((0.20, "slight"), (0.40, "fair"), (0.60, "moderate"), (0.80, "substantial")):
        if kappa <= upper:
            return label
    return "almost perfect"


def _ratio(num, den):
    return round(num / den, 4) if den else None


def binary_metrics(predicted, truth) -> dict:
    """Confusion matrix, precision/recall/F1/accuracy and kappa for a binary detector."""
    pairs = [(bool(p), bool(t)) for p, t in zip(predicted, truth)]
    tp = sum(p and t for p, t in pairs)
    fp = sum(p and not t for p, t in pairs)
    fn = sum(t and not p for p, t in pairs)
    tn = sum(not p and not t for p, t in pairs)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)  # = 2PR / (P + R), defined even when tp = 0
    kappa = cohen_kappa([p for p, _ in pairs], [t for _, t in pairs]) if pairs else None
    return {
        "n": len(pairs), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": _ratio(tp + tn, len(pairs)),
        "kappa": round(kappa, 4) if kappa is not None else None,
    }


# --------------------------------------------------------------- export

def load_records(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def export_labelling_sheet(records: list, out_path: str, n: int | None = None, seed: int = 7):
    """Write a blind labelling sheet and its key. Returns (sheet, key, count)."""
    rng = random.Random(seed)
    strata = {}
    for record in records:
        strata.setdefault((record["attack_id"], bool(record["success"])), []).append(record)
    for bucket in strata.values():
        rng.shuffle(bucket)
    wanted = len(records) if n is None else min(n, len(records))
    picked = []
    while len(picked) < wanted:  # round-robin so every attack x outcome is represented
        before = len(picked)
        for key in sorted(strata):
            if strata[key] and len(picked) < wanted:
                picked.append(strata[key].pop())
        if len(picked) == before:
            break
    rng.shuffle(picked)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    key_path = os.path.splitext(out_path)[0] + "_key.csv"
    with open(out_path, "w", encoding="utf-8-sig", newline="") as sheet, \
            open(key_path, "w", encoding="utf-8-sig", newline="") as key:
        sheet_writer = csv.DictWriter(sheet, fieldnames=SHEET_FIELDS)
        key_writer = csv.DictWriter(key, fieldnames=KEY_FIELDS)
        sheet_writer.writeheader()
        key_writer.writeheader()
        for i, r in enumerate(picked, 1):
            sample_id = f"S{i:03d}"
            reply = r["response"]
            if r.get("context"):
                reply = f"[earlier reply] {r['context']}\n[reply to the probe] {r['response']}"
            sheet_writer.writerow({
                "sample_id": sample_id, "vulnerability_class": r["vulnerability_class"],
                "attack": r["attack_name"], "objective": r.get("objective", ""), "prompt": r["prompt"],
                "assistant_reply": reply, "label_success": "", "label_severity": "", "notes": "",
            })
            key_writer.writerow({
                "sample_id": sample_id, "target": r["target"], "config": r["config"], "trial": r["trial"],
                "attack_id": r["attack_id"], "probe_id": r["probe_id"], "auto_success": int(bool(r["success"])),
                "auto_risk": r["risk_score"], "auto_severity": r["severity"],
                "ground_truth": "" if r.get("ground_truth") is None else int(bool(r["ground_truth"])),
            })
    return out_path, key_path, len(picked)


# ------------------------------------------------------------ agreement

def _read_labels(path: str) -> dict:
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    labels = {}
    for row in rows:
        success = (row.get("label_success") or "").strip()
        severity = (row.get("label_severity") or "").strip()
        if success == "":
            continue
        labels[row["sample_id"]] = {
            "success": int(float(success)),
            "severity": int(float(severity)) if severity != "" else None,
        }
    return labels


def agreement_report(path_a: str, path_b: str, key_path: str | None = None) -> dict:
    a, b = _read_labels(path_a), _read_labels(path_b)
    common = sorted(set(a) & set(b))
    if not common:
        raise ValueError("No sample was labelled by both annotators.")
    success_a = [a[i]["success"] for i in common]
    success_b = [b[i]["success"] for i in common]
    kappa = cohen_kappa(success_a, success_b)
    report = {
        "n_common": len(common),
        "inter_annotator": {
            "percent_agreement": round(sum(x == y for x, y in zip(success_a, success_b)) / len(common), 4),
            "kappa_success": None if kappa is None else round(kappa, 4),
            "interpretation": interpret_kappa(kappa),
        },
    }
    both_sev = [i for i in common if a[i]["severity"] is not None and b[i]["severity"] is not None]
    if both_sev:
        wk = weighted_kappa([a[i]["severity"] for i in both_sev], [b[i]["severity"] for i in both_sev], k=5)
        report["inter_annotator"]["weighted_kappa_severity"] = None if wk is None else round(wk, 4)

    if key_path:
        with open(key_path, encoding="utf-8-sig", newline="") as f:
            key = {row["sample_id"]: row for row in csv.DictReader(f)}
        consensus = [i for i in common if a[i]["success"] == b[i]["success"] and i in key]
        human = [bool(a[i]["success"]) for i in consensus]
        auto = [key[i]["auto_success"].strip() in ("1", "True", "true") for i in consensus]
        section = {"n_consensus": len(consensus)}
        if consensus:
            section["detector_vs_human"] = binary_metrics(auto, human)
            section["interpretation"] = interpret_kappa(section["detector_vs_human"]["kappa"])
        rated = [i for i in both_sev if i in key]
        if len(rated) >= 3:
            rho = spearman([(a[i]["severity"] + b[i]["severity"]) / 2 for i in rated],
                           [float(key[i]["auto_risk"]) for i in rated])
            section["spearman_severity_vs_risk"] = None if rho is None else round(rho, 4)
        report["human_vs_automated"] = section
    return report


# ------------------------------------------------------------------ CLI

def main(argv=None):
    parser = argparse.ArgumentParser(description="SentinelAI human-validation tools")
    sub = parser.add_subparsers(dest="command", required=True)

    exp = sub.add_parser("export", help="write a blind labelling sheet from records.jsonl")
    exp.add_argument("--records", required=True)
    exp.add_argument("--out", required=True)
    exp.add_argument("--n", type=int, default=None, help="sample size (default: all records)")
    exp.add_argument("--seed", type=int, default=7)

    agr = sub.add_parser("agreement", help="compute agreement between two labelled sheets")
    agr.add_argument("--a", required=True)
    agr.add_argument("--b", required=True)
    agr.add_argument("--key", default=None)

    args = parser.parse_args(argv)
    if args.command == "export":
        sheet, key, count = export_labelling_sheet(load_records(args.records), args.out, args.n, args.seed)
        print(f"Wrote {count} samples to {sheet} (give this to annotators) and the key to {key} (keep hidden).")
        print("Labels: label_success 0/1; label_severity 0 None, 1 Low, 2 Medium, 3 High, 4 Critical.")
    else:
        print(json.dumps(agreement_report(args.a, args.b, args.key), indent=2))


if __name__ == "__main__":
    main()
