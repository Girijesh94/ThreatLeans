"""Reproducible retrieval measurements over an explicitly enumerated workload."""

import json
import statistics
import time
from pathlib import Path

from .pipeline import investigate
from .retrieval import retriever
from .store import initialize

CASES = [
    ("What is known about CVE-2021-44228?", "KEV:CVE-2021-44228"),
    ("CVE-2023-34362", "KEV:CVE-2023-34362"),
    ("CVE-2024-3094", "NVD:CVE-2024-3094"),
    ("CVE-2017-0144", "KEV:CVE-2017-0144"),
    ("CVE-2021-26855", "KEV:CVE-2021-26855"),
    ("CVE-2023-4966", "KEV:CVE-2023-4966"),
    ("Explain T1566", "ATTACK:T1566"),
    ("Explain T1059", "ATTACK:T1059"),
    ("Explain T1078", "ATTACK:T1078"),
    ("Explain T1486", "ATTACK:T1486"),
    ("Explain G0016", "ATTACK:G0016"),
    ("phishing", "ATTACK:T1566"),
    ("data encrypted for impact", "ATTACK:T1486"),
    ("valid accounts", "ATTACK:T1078"),
    ("CVE-2099-999999", None),
    ("CVE-2088-777777", None),
]


async def evaluate(output: Path):
    initialize()
    retriever.refresh()
    rows = []
    for question, expected in CASES:
        start = time.perf_counter()
        result = await investigate(question)
        identifiers = [e["id"] for e in result["evidence"]]
        passed = expected in identifiers if expected else not identifiers
        rows.append(
            {
                "question": question,
                "expected_id": expected,
                "retrieved_ids": identifiers,
                "retrieval_pass": passed,
                "status": result["status"],
                "claim_count": len(result["claims"]),
                "supported_claim_count": sum(c["status"] == "supported" for c in result["claims"]),
                "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
            }
        )
    durations = sorted(r["elapsed_ms"] for r in rows)
    report = {
        "corpus_generation": result["corpus_generation"],
        "retrieval_mode": retriever.mode,
        "case_count": len(rows),
        "retrieval_pass_rate": sum(r["retrieval_pass"] for r in rows) / len(rows),
        "median_ms": statistics.median(durations),
        "p95_ms": durations[min(len(rows) - 1, int(len(rows) * 0.95))],
        "scope": "Fixed small retrieval workload; not a general intelligence accuracy benchmark. No paid provider calls.",
        "cases": rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
