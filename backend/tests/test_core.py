import pytest
from fastapi.testclient import TestClient

from threatleans.ingest import normalize_attack, normalize_kev
from threatleans.main import app
from threatleans.pipeline import claims, verify


def test_kev_preserves_unknown_ransomware_and_action():
    row = next(
        normalize_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "requiredAction": "Apply updates.",
                        "knownRansomwareCampaignUse": "Unknown",
                        "vulnerabilityName": "RCE",
                        "shortDescription": "A flaw.",
                    }
                ]
            }
        )
    )
    assert row["facts"]["ransomware"] == "Unknown"
    assert row["facts"]["kev"] is True
    assert "scores" not in row["facts"]


def test_attack_skips_revoked():
    payload = {"objects": [{"type": "attack-pattern", "revoked": True}]}
    assert list(normalize_attack(payload)) == []


def test_verifier_rejects_fabricated_field():
    state = {
        "trace": [],
        "evidence": [{"facts": {"kev": True}, "sha256": "hash"}],
        "claims": [{"field": "kev", "value": False, "evidence": ["E1"], "text": "fabricated"}],
    }
    assert verify(state)["claims"][0]["status"] == "unsupported"


def test_versioned_cvss_claim_preserves_source():
    score = {"version": "3.1", "score": 9.8, "source": "cna@example.test", "type": "Primary"}
    state = {
        "trace": [],
        "evidence": [{"facts": {"cve": "CVE-2020-0001", "scores": [score]}, "sha256": "hash"}],
    }
    result = verify(claims(state))
    assert result["claims"][0]["status"] == "supported"
    assert "3.1" in result["claims"][0]["text"]
    assert "cna@example.test" in result["claims"][0]["text"]


def test_api_roundtrip_and_unknown():
    with TestClient(app) as client:
        me = client.get("/api/auth/me")
        if me.status_code == 401:
            pytest.skip("Test local profile only; auth integration uses isolated subprocess")
        response = client.post("/api/investigate", json={"question": "CVE-2099-999999"})
        assert response.status_code == 200
        body = response.json()
        assert body["result"]["evidence"] == []
        assert body["result"]["status"] == "needs_review"
        assert body["review_status"] == "pending"
        export = client.get(f"/api/investigations/{body['id']}/export")
        assert export.status_code == 200
        assert export.json()["id"] == body["id"]


def test_cloud_requires_explicit_sharing():
    with TestClient(app) as client:
        if client.get("/api/auth/me").status_code == 401:
            pytest.skip("Local test profile only")
        result = client.post("/api/investigate", json={"question": "Log4Shell", "provider": "openai"})
        assert result.status_code == 400


def test_public_demo_cannot_select_arbitrary_questions_or_ai(monkeypatch):
    import threatleans.main as main

    calls = []

    async def sample(question, provider, online):
        calls.append((question, provider, online))
        return {"claims": [], "evidence": [], "ai": None}

    monkeypatch.setattr(main, "investigate", sample)
    with TestClient(app) as client:
        assert client.get("/api/public/demo?example=arbitrary").status_code == 422
        response = client.get("/api/public/demo?example=technique&provider=openai&online=true")
        assert response.status_code == 200
        assert response.json()["ai"] is None
    assert calls == [("T1566", "evidence", False)]
