"""A bounded LangGraph workflow. Claims are derived from stored structured facts."""

import asyncio
import re
import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .gateway import route_summary
from .ingest import ingest_cve, ingest_nvd
from .retrieval import retriever


class State(TypedDict, total=False):
    question: str
    provider: str
    online: bool
    evidence: list
    claims: list
    trace: list
    warnings: list
    result: dict
    live_checks: list


def event(state, role, detail):
    state.setdefault("trace", []).append({"role": role, "detail": detail})


async def plan(state):
    state["trace"], state["warnings"] = [], []
    state["live_checks"] = []
    event(
        state,
        "Planner",
        "Identify requested entities; search authoritative sources; verify structured facts.",
    )
    if state.get("online"):
        ids = list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,}\b", state["question"].upper())))[:3]

        async def check(source, fetch, cve):
            try:
                await fetch(cve)
                state["live_checks"].append({"source": source, "cve": cve, "status": "checked"})
            except Exception as exc:
                state["warnings"].append(
                    f"Live {source} check failed for {cve}: {type(exc).__name__}. Cached evidence remains available."
                )
                state["live_checks"].append({"source": source, "cve": cve, "status": "failed"})

        await asyncio.gather(
            *(
                check(source, fetch, cve)
                for cve in ids
                for source, fetch in [("NVD", ingest_nvd), ("CVE Program", ingest_cve)]
            )
        )
        if ids:
            retriever.refresh()
    return state


def retrieve(state):
    state["evidence"] = retriever.search(state["question"], limit=8)
    event(state, "Retriever", f"Retrieved {len(state['evidence'])} records using {retriever.mode} search.")
    return state


def claims(state):
    rows = []
    for i, e in enumerate(state["evidence"], 1):
        ref = f"E{i}"
        facts = e["facts"]
        if facts.get("cve"):
            if facts.get("kev"):
                rows.extend(
                    [
                        {
                            "text": f"{facts['cve']} is listed in CISA's Known Exploited Vulnerabilities catalog.",
                            "field": "kev",
                            "value": True,
                            "evidence": [ref],
                        },
                        {
                            "text": f"CISA's required action: {facts['required_action']}",
                            "field": "required_action",
                            "value": facts["required_action"],
                            "evidence": [ref],
                        },
                    ]
                )
            for score in facts.get("scores", []):
                rows.append(
                    {
                        "text": f"{facts['cve']} has CVSS {score['version']} score {score['score']} "
                        f"reported by {score['source']} ({score['type']}).",
                        "field": "scores",
                        "value": score,
                        "evidence": [ref],
                    }
                )
        elif facts.get("attack_id"):
            rows.append(
                {
                    "text": f"{facts['attack_id']} is {facts['name']} in MITRE ATT&CK.",
                    "field": "name",
                    "value": facts["name"],
                    "evidence": [ref],
                }
            )
            if facts.get("tactics"):
                rows.append(
                    {
                        "text": "Associated tactics: " + ", ".join(facts["tactics"]) + ".",
                        "field": "tactics",
                        "value": facts["tactics"],
                        "evidence": [ref],
                    }
                )
            for relationship in facts.get("relationships", [])[:4]:
                rows.append(
                    {
                        "text": f"MITRE records {facts['attack_id']} {relationship['relationship']} {relationship['target']} ({relationship['target_name']}).",
                        "field": "relationships",
                        "value": relationship,
                        "evidence": [ref],
                    }
                )
        if e.get("excerpt"):
            quotation = e["excerpt"][:450]
            rows.append(
                {
                    "text": "Source excerpt: “" + quotation + "”",
                    "field": "source_excerpt",
                    "value": quotation,
                    "evidence": [ref],
                }
            )
    state["claims"] = rows[:24]
    event(
        state,
        "Fact builder",
        f"Built {len(state['claims'])} source-bound claims; no generative model required.",
    )
    return state


def verify(state):
    refs = {f"E{i}": e for i, e in enumerate(state["evidence"], 1)}
    for claim in state["claims"]:
        evidence = refs[claim["evidence"][0]]
        actual = evidence["facts"].get(claim["field"])
        if claim["field"] == "source_excerpt":
            valid = evidence["excerpt"].startswith(claim["value"])
        else:
            valid = (
                claim["value"] in actual
                if claim["field"] in {"scores", "relationships"}
                else actual == claim["value"]
            )
        claim["status"] = "supported" if valid else "unsupported"
        claim["corroborated_by"] = []
        if valid and claim["field"] == "scores":
            for ref, other in refs.items():
                if other.get("source") == evidence.get("source") or other["facts"].get("cve") != evidence[
                    "facts"
                ].get("cve"):
                    continue
                score = claim["value"]
                if any(
                    s["version"] == score["version"]
                    and s["score"] == score["score"]
                    and s.get("vector") == score.get("vector")
                    for s in other["facts"].get("scores", [])
                ):
                    claim["corroborated_by"].append(ref)
        claim["source_hash"] = evidence["sha256"]
    event(
        state, "Verifier", "Compared every claim to its cited structured field; provenance hashes retained."
    )
    return state


async def synthesize(state):
    evidence = state["evidence"]
    supported = [c for c in state["claims"] if c["status"] == "supported"]
    status = "supported" if supported else "insufficient_evidence"
    if not re.search(r"\b(?:CVE-\d{4}-\d{4,}|[TGS]\d{4}(?:\.\d{3})?)\b", state["question"], re.IGNORECASE):
        status = "needs_review" if evidence else "insufficient_evidence"
        if evidence:
            state["warnings"].append(
                "This conceptual search found related evidence; relevance and interpretation require analyst judgment."
            )
    ids = re.findall(r"\bCVE-\d{4}-\d{4,}\b", state["question"].upper())
    missing = [cve for cve in ids if not any(e["facts"].get("cve") == cve for e in evidence)]
    if missing:
        state["warnings"].append(
            "No indexed evidence for " + ", ".join(missing) + ". Absence does not establish safety."
        )
        status = "needs_review"
    if evidence and not supported:
        status = "needs_review"
    if re.search(
        r"am i affected|are we affected|our (?:system|server)|is my|compromised",
        state["question"],
        re.IGNORECASE,
    ):
        state["warnings"].append(
            "Applicability cannot be established from a product-name match. Supply exact product, version, edition, configuration and a vendor applicability rule; review against your assets."
        )
        status = "needs_review"
    if re.search(r"cvss|severity|score", state["question"], re.IGNORECASE) and not any(
        e["facts"].get("scores") for e in evidence
    ):
        state["warnings"].append(
            "The retrieved sources contain no CVSS metrics. Enable a live NVD check for a named CVE or request review."
        )
        status = "needs_review"
    for cve in ids:
        versions = {}
        for e in evidence:
            if e["facts"].get("cve") == cve:
                for score in e["facts"].get("scores", []):
                    versions.setdefault(score["version"], set()).add(score["score"])
        if any(len(values) > 1 for values in versions.values()):
            status = "needs_review"
            state["warnings"].append(
                f"{cve} has differing scores within a CVSS version; inspect reporting sources before choosing a score."
            )
    prose = "\n\n".join(c["text"] + " " + " ".join(f"[{r}]" for r in c["evidence"]) for c in supported)
    if not prose:
        prose = "The indexed sources do not support a factual answer to this question. Inspect the matching evidence or request analyst review."
    result = {
        "answer": prose,
        "status": status,
        "claims": state["claims"],
        "evidence": evidence,
        "retrieval_mode": retriever.mode,
        "trace": state["trace"],
        "warnings": state["warnings"],
        "ai": None,
        "limitations": [
            "Source-bound verification checks the recorded fields, not independent real-world truth.",
            "Retrieved excerpts are evidence to inspect, not verified causal links or attribution.",
            "CISA deadlines apply to US federal civilian agencies; prioritize locally using your assets.",
        ],
    }
    import hashlib

    result["corpus_generation"] = hashlib.sha256(
        "".join(d.sha256 for d in retriever.docs).encode()
    ).hexdigest()[:16]
    result["live_checks"] = state.get("live_checks", [])
    result["verification_mode"] = (
        "live source checks recorded" if result["live_checks"] else "recorded source fields"
    )
    if state.get("provider", "evidence") != "evidence" and evidence:
        try:
            result["ai"] = await route_summary(state["provider"], state["question"], evidence)
        except Exception as exc:
            result["warnings"].append(
                f"Optional AI summary unavailable ({type(exc).__name__}); evidence answer retained."
            )
    event(state, "Decision", "Return supported facts; route unresolved questions to human review.")
    state["result"] = result
    return state


builder = StateGraph(State)
for name, fn in [
    ("plan", plan),
    ("retrieve", retrieve),
    ("claims", claims),
    ("verify", verify),
    ("synthesize", synthesize),
]:
    builder.add_node(name, fn)
builder.add_edge(START, "plan")
for a, b in [("plan", "retrieve"), ("retrieve", "claims"), ("claims", "verify"), ("verify", "synthesize")]:
    builder.add_edge(a, b)
builder.add_edge("synthesize", END)
graph = builder.compile()


async def investigate(question, provider="evidence", online=False):
    start = time.perf_counter()
    state = await graph.ainvoke({"question": question, "provider": provider, "online": online})
    result = state["result"]
    result["elapsed_ms"] = round((time.perf_counter() - start) * 1000)
    return result
