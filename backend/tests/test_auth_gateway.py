import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatleans.auth import hasher
from threatleans.config import get_settings
from threatleans.gateway import circuits, summarize
from threatleans.main import app
from threatleans.store import DB, User, initialize


def test_shared_auth_csrf_and_roles(monkeypatch):
    initialize()
    with DB.begin() as db:
        for name, role in [("test-admin", "admin"), ("test-analyst", "analyst")]:
            existing = db.scalar(select(User).where(User.username == name))
            if not existing:
                db.add(User(username=name, role=role, password_hash=hasher.hash("Test-password-123!")))
    s = get_settings()
    monkeypatch.setattr(s, "auth_required", True)
    monkeypatch.setattr(s, "admin_username", "test-admin")
    with TestClient(app) as client:
        assert client.get("/api/history").status_code == 401
        signed = client.post(
            "/api/auth/login", json={"username": "test-analyst", "password": "Test-password-123!"}
        )
        assert signed.status_code == 200
        assert "HttpOnly" in signed.headers["set-cookie"]
        csrf = signed.json()["csrf"]
        assert client.post("/api/investigate", json={"question": "Unknown question"}).status_code == 403
        assert client.get("/api/admin/users").status_code == 403
        assert client.get("/api/reviews").status_code == 403
        assert (
            client.post(
                "/api/investigate", json={"question": "Unknown question"}, headers={"X-CSRF-Token": csrf}
            ).status_code
            == 200
        )
        assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
        assert client.get("/api/history").status_code == 401


@pytest.mark.asyncio
async def test_openai_schema_and_secret_stays_server(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "openai_api_key", "test-secret")
    monkeypatch.setattr(s, "openai_model", "test-model")
    circuits.clear()
    with respx.mock as mock:
        route = mock.post("https://api.openai.com/v1/responses").mock(
            return_value=httpx.Response(
                200,
                json={
                    "output": [
                        {"content": [{"type": "output_text", "text": '{"summary":"Observed fact [E1]."}'}]}
                    ]
                },
            )
        )
        result = await summarize("openai", "Question", [{"excerpt": "Source fact", "facts": {}}])
        assert result["verification"] == "unverified AI interpretation"
        request = json.loads(route.calls.last.request.content)
        assert request["text"]["format"]["strict"] is True
        assert "test-secret" not in json.dumps(result)


@pytest.mark.asyncio
async def test_provider_failure_opens_circuit(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "anthropic_api_key", "test-secret")
    monkeypatch.setattr(s, "anthropic_model", "test-model")
    circuits.clear()
    with respx.mock as mock:
        route = mock.post("https://api.anthropic.com/v1/messages").mock(return_value=httpx.Response(429))
        with pytest.raises(httpx.HTTPStatusError):
            await summarize("anthropic", "Q", [])
        with pytest.raises(RuntimeError, match="cooling down"):
            await summarize("anthropic", "Q", [])
        assert route.call_count == 1


@pytest.mark.asyncio
async def test_real_routing_contract_fails_over(monkeypatch):
    from threatleans.gateway import route_summary

    s = get_settings()
    for field, value in [
        ("openai_api_key", "test"),
        ("openai_model", "test"),
        ("anthropic_api_key", "test"),
        ("anthropic_model", "test"),
        ("ollama_model", ""),
    ]:
        monkeypatch.setattr(s, field, value)
    circuits.clear()
    with respx.mock as mock:
        mock.post("https://api.openai.com/v1/responses").mock(return_value=httpx.Response(503))
        mock.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(
                200, json={"content": [{"type": "text", "text": '{"summary":"Source fact [E1]."}'}]}
            )
        )
        result = await route_summary("openai", "Question", [])
        assert result["provider"] == "anthropic"
        assert [a["status"] for a in result["attempts"]] == ["failed", "success"]
