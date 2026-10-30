import csv

from sentinelai_harness.validation import (
    agreement_report,
    binary_metrics,
    cohen_kappa,
    export_labelling_sheet,
    interpret_kappa,
    spearman,
    weighted_kappa,
)

# Textbook example: 50 items, 20 yes/yes, 5 yes/no, 10 no/yes, 15 no/no
# -> p_o = 0.70, p_e = 0.50, kappa = 0.40
RATER_A = [1] * 20 + [1] * 5 + [0] * 10 + [0] * 15
RATER_B = [1] * 20 + [0] * 5 + [1] * 10 + [0] * 15


def test_cohen_kappa_textbook_example():
    assert abs(cohen_kappa(RATER_A, RATER_B) - 0.4) < 1e-9


def test_kappa_edge_cases():
    assert cohen_kappa([1, 0, 1], [1, 0, 1]) == 1.0
    assert cohen_kappa([1, 1], [1, 1]) is None


def test_weighted_kappa_equals_cohen_for_binary_and_rewards_near_misses():
    assert abs(weighted_kappa(RATER_A, RATER_B) - cohen_kappa(RATER_A, RATER_B)) < 1e-9
    truth = [0, 1, 2, 3, 4, 4, 2]
    near = [0, 1, 3, 3, 4, 3, 2]
    far = [4, 1, 0, 3, 0, 3, 2]
    assert weighted_kappa(truth, near, k=5) > weighted_kappa(truth, far, k=5)


def test_spearman():
    assert abs(spearman([1, 2, 3, 4], [10, 20, 30, 40]) - 1.0) < 1e-9
    assert abs(spearman([1, 2, 3, 4], [4, 3, 2, 1]) + 1.0) < 1e-9
    assert spearman([1, 1, 1], [1, 2, 3]) is None


def test_binary_metrics():
    m = binary_metrics([True, True, False, False], [True, False, True, False])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5 and m["kappa"] == 0.0


def test_interpret_kappa():
    assert interpret_kappa(0.85) == "almost perfect"
    assert interpret_kappa(0.5) == "moderate"
    assert interpret_kappa(None) == "undefined"


def test_export_is_blind_and_agreement_round_trips(tmp_path):
    records = [{
        "attack_id": "a" if i % 2 else "b", "attack_name": "A", "vulnerability_class": "prompt_injection",
        "success": i % 3 == 0, "objective": "o", "prompt": f"p{i}", "context": "", "response": f"r{i}",
        "target": "t", "config": "model", "trial": 1, "probe_id": f"x{i}", "risk_score": float(i * 10),
        "severity": "Low", "ground_truth": None,
    } for i in range(10)]
    sheet, key, n = export_labelling_sheet(records, str(tmp_path / "sheet.csv"), n=8)
    assert n == 8
    with open(sheet, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert not any("auto" in col or "risk" in col for col in rows[0])  # annotators never see scores
    with open(key, encoding="utf-8-sig", newline="") as f:
        auto = {r["sample_id"]: int(r["auto_success"]) for r in csv.DictReader(f)}

    def write_labels(path, flip=None):
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                label = auto[row["sample_id"]]
                if row["sample_id"] == flip:
                    label = 1 - label
                writer.writerow(dict(row, label_success=label, label_severity=3 if label else 0))

    write_labels(tmp_path / "a.csv")
    write_labels(tmp_path / "b.csv", flip=rows[0]["sample_id"])
    report = agreement_report(str(tmp_path / "a.csv"), str(tmp_path / "b.csv"), key)
    assert report["n_common"] == 8
    assert report["inter_annotator"]["percent_agreement"] == 0.875
    assert report["human_vs_automated"]["detector_vs_human"]["kappa"] == 1.0
