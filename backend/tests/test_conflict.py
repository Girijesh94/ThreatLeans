import pytest

from threatleans.pipeline import synthesize


@pytest.mark.asyncio
async def test_synthetic_same_version_conflict_routes_to_review():
    evidence = [
        {
            "id": "fixture:a",
            "source": "Synthetic NVD fixture",
            "facts": {
                "cve": "CVE-2020-0001",
                "scores": [{"version": "3.1", "score": 9.8, "source": "a", "type": "Primary", "vector": "v"}],
            },
        },
        {
            "id": "fixture:b",
            "source": "Synthetic CNA fixture",
            "facts": {
                "cve": "CVE-2020-0001",
                "scores": [{"version": "3.1", "score": 7.5, "source": "b", "type": "CNA", "vector": "w"}],
            },
        },
    ]
    state = {
        "question": "CVE-2020-0001",
        "provider": "evidence",
        "trace": [],
        "warnings": [],
        "evidence": evidence,
        "claims": [],
    }
    result = (await synthesize(state))["result"]
    assert result["status"] == "needs_review"
    assert any("differing scores" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_different_cvss_versions_are_not_a_conflict():
    evidence = [
        {
            "id": "fixture:a",
            "facts": {
                "cve": "CVE-2020-0001",
                "scores": [{"version": "2.0", "score": 7.5}, {"version": "3.1", "score": 9.8}],
            },
        }
    ]
    state = {
        "question": "CVE-2020-0001",
        "provider": "evidence",
        "trace": [],
        "warnings": [],
        "evidence": evidence,
        "claims": [{"text": "fact", "evidence": ["E1"], "status": "supported"}],
    }
    result = (await synthesize(state))["result"]
    assert not any("differing scores" in w for w in result["warnings"])
