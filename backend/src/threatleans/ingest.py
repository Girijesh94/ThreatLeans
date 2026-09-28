"""Allowlisted public feeds. Raw bytes are retained by content hash."""

import asyncio
import json
import re
import time

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from .config import get_settings
from .store import DB, Document, Ingestion, digest, initialize, now

FEEDS = {
    "kev": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "owasp": "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/index.md",
}
nvd_lock = asyncio.Lock()
nvd_last_request = 0.0


def clean(text):
    return re.sub(r"\s+", " ", BeautifulSoup(text, "html.parser").get_text(" ")).strip()


def persist(items, fetched):
    with DB.begin() as db:
        for item in items:
            item["sha256"] = digest(json.dumps(item, sort_keys=True))
            item["fetched_at"] = fetched
            db.merge(Document(**item))
    return len(items)


def archive(source, raw):
    import hashlib

    path = get_settings().resolved_data_dir / "raw" / source
    path.mkdir(parents=True, exist_ok=True)
    (path / (hashlib.sha256(raw).hexdigest() + ".json")).write_bytes(raw)


def normalize_kev(payload):
    for v in payload["vulnerabilities"]:
        facts = {
            "cve": v["cveID"],
            "vendor": v["vendorProject"],
            "product": v["product"],
            "kev": True,
            "date_added": v["dateAdded"],
            "due_date": v["dueDate"],
            "required_action": v["requiredAction"],
            "ransomware": v["knownRansomwareCampaignUse"],
            "cwe": v.get("cwes", []),
            "notes": v.get("notes", ""),
        }
        yield {
            "id": "KEV:" + v["cveID"],
            "title": v["cveID"] + " · " + v["vulnerabilityName"],
            "kind": "vulnerability",
            "source": "CISA KEV",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + v["cveID"],
            "text": f"{v['shortDescription']} Required action: {v['requiredAction']} {v.get('notes', '')}",
            "facts": facts,
        }


def normalize_attack(payload):
    objects = {o["id"]: o for o in payload["objects"] if o.get("id")}
    links = {}
    for relation in payload["objects"]:
        if (
            relation["type"] != "relationship"
            or relation.get("revoked")
            or relation.get("x_mitre_deprecated")
        ):
            continue
        target = objects.get(relation.get("target_ref"), {})
        if target.get("revoked") or target.get("x_mitre_deprecated"):
            continue
        refs = [
            r
            for r in target.get("external_references", [])
            if r.get("source_name") == "mitre-attack" and r.get("external_id")
        ]
        if refs:
            links.setdefault(relation["source_ref"], []).append(
                {
                    "relationship": relation["relationship_type"],
                    "target": refs[0]["external_id"],
                    "target_name": target.get("name", ""),
                    "stix_relationship_id": relation["id"],
                    "description": clean(relation.get("description", ""))[:800],
                }
            )
    for obj in payload["objects"]:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        kind = {
            "attack-pattern": "technique",
            "intrusion-set": "group",
            "malware": "software",
            "tool": "software",
            "course-of-action": "mitigation",
        }.get(obj["type"])
        refs = [r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if not kind or not refs or "external_id" not in refs[0]:
            continue
        ref = refs[0]
        yield {
            "id": "ATTACK:" + ref["external_id"],
            "title": ref["external_id"] + " · " + obj["name"],
            "kind": kind,
            "source": "MITRE ATT&CK",
            "url": ref.get("url", "https://attack.mitre.org/"),
            "text": clean(obj.get("description", "")),
            "facts": {
                "attack_id": ref["external_id"],
                "name": obj["name"],
                "aliases": obj.get("aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                "modified": obj.get("modified"),
                "stix_id": obj["id"],
                "relationships": links.get(obj["id"], []),
            },
        }


async def ingest_source(source):
    initialize()
    if source not in FEEDS:
        raise ValueError("Unknown source")
    with DB.begin() as db:
        run = Ingestion(source=source, status="running")
        db.add(run)
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            response = await client.get(FEEDS[source])
            response.raise_for_status()
        raw = response.content
        if len(raw) > 80_000_000:
            raise ValueError("Feed exceeds size limit")
        path = get_settings().resolved_data_dir / "raw" / source
        path.mkdir(parents=True, exist_ok=True)
        import hashlib

        (path / (hashlib.sha256(raw).hexdigest() + ".json")).write_bytes(raw)
        if source == "owasp":
            items = [
                {
                    "id": "OWASP:TOP10:2021",
                    "title": "OWASP Top 10 · 2021 edition",
                    "kind": "guidance",
                    "source": "OWASP",
                    "url": "https://owasp.org/Top10/2021/",
                    "text": raw.decode("utf-8"),
                    "facts": {"edition": "2021"},
                }
            ]
        else:
            payload = json.loads(raw)
            items = list(normalize_kev(payload) if source == "kev" else normalize_attack(payload))
        if not items:
            raise ValueError("Empty feed rejected; previous evidence retained")
        count = persist(items, now())
        # Remove records withdrawn from a complete authoritative snapshot.
        current_ids = {item["id"] for item in items}
        source_name = {"kev": "CISA KEV", "attack": "MITRE ATT&CK", "owasp": "OWASP"}[source]
        with DB.begin() as db:
            for stale in db.scalars(select(Document).where(Document.source == source_name)):
                if stale.id not in current_ids:
                    db.delete(stale)
        with DB.begin() as db:
            r = db.get(Ingestion, run.id)
            r.status, r.count = "complete", count
        return {"source": source, "count": count, "status": "complete"}
    except Exception as exc:
        with DB.begin() as db:
            r = db.get(Ingestion, run.id)
            r.status, r.error = "failed", str(exc)[:500]
        raise


async def ingest_nvd(cve):
    global nvd_last_request
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise ValueError("Invalid CVE")
    settings = get_settings()
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    async with nvd_lock:
        delay = max(0, (0.7 if settings.nvd_api_key else 6.1) - (time.monotonic() - nvd_last_request))
        if delay:
            await asyncio.sleep(delay)
        nvd_last_request = time.monotonic()
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, headers=headers
            )
            response.raise_for_status()
    entries = response.json().get("vulnerabilities", [])
    archive("nvd", response.content)
    items = []
    for entry in entries:
        v = entry["cve"]
        scores = [
            {
                "version": m["cvssData"].get("version"),
                "score": m["cvssData"]["baseScore"],
                "vector": m["cvssData"].get("vectorString"),
                "source": m["source"],
                "type": m["type"],
            }
            for group in v.get("metrics", {}).values()
            for m in group
            if "cvssData" in m
        ]
        items.append(
            {
                "id": "NVD:" + cve,
                "title": cve + " · NVD record",
                "kind": "vulnerability",
                "source": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/" + cve,
                "text": " ".join(d["value"] for d in v["descriptions"] if d["lang"] == "en"),
                "facts": {
                    "cve": cve,
                    "scores": scores,
                    "status": v.get("vulnStatus"),
                    "published": v.get("published"),
                    "modified": v.get("lastModified"),
                    "references": v.get("references", []),
                },
            }
        )
    return persist(items, now())


async def ingest_cve(cve):
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise ValueError("Invalid CVE")
    _, year, number = cve.split("-")
    bucket = str(int(number) // 1000) + "xxx"
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(url)
        response.raise_for_status()
    body = response.json()
    archive("cve", response.content)
    cna = body["containers"]["cna"]
    scores = []
    for metric in cna.get("metrics", []):
        for key, value in metric.items():
            if key.startswith("cvss") and isinstance(value, dict) and "baseScore" in value:
                scores.append(
                    {
                        "version": value.get("version"),
                        "score": value["baseScore"],
                        "vector": value.get("vectorString"),
                        "source": cna.get("providerMetadata", {}).get("shortName", "CNA"),
                        "type": "CNA",
                    }
                )
    return persist(
        [
            {
                "id": "CVE:" + cve,
                "title": cve + " · CVE Program CNA record",
                "kind": "vulnerability",
                "source": "CVE Program",
                "url": "https://www.cve.org/CVERecord?id=" + cve,
                "text": " ".join(
                    d["value"] for d in cna.get("descriptions", []) if d["lang"].startswith("en")
                ),
                "facts": {
                    "cve": cve,
                    "scores": scores,
                    "affected": cna.get("affected", []),
                    "state": body["cveMetadata"]["state"],
                    "references": cna.get("references", []),
                    "modified": body["cveMetadata"].get("dateUpdated"),
                },
            }
        ],
        now(),
    )
