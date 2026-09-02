from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from jose import jwt

from api import auth


LEGACY_SECRET = "legacy-auth-secret-with-at-least-thirty-two-characters"
PROXY_SECRET = "proxy-auth-secret-with-at-least-thirty-two-characters"


def request(method: str, path: str) -> Request:
    return Request({"type": "http", "method": method, "path": path, "headers": []})


@pytest.fixture(autouse=True)
def configured_secrets(monkeypatch):
    monkeypatch.setattr(auth, "JWT_SECRET", LEGACY_SECRET)
    monkeypatch.setattr(auth, "SOTYHUB_PROXY_JWT_SECRET", PROXY_SECRET)


def proxy_token(path: str = "/execute", method: str = "POST", **overrides) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": auth.SOTYHUB_PROXY_ISSUER,
        "aud": auth.SOTYHUB_PROXY_AUDIENCE,
        "sub": "firebase-user-1",
        "token_use": "sotyhub_proxy",
        "bofa_path": path,
        "bofa_method": method,
        "iat": now,
        "exp": now + timedelta(seconds=60),
        "jti": "test-jti",
        **overrides,
    }
    return jwt.encode(payload, PROXY_SECRET, algorithm="HS256")


def test_accepts_a_bounded_sotyhub_proxy_token():
    manager = auth.AuthManager(database_manager=None)
    token = proxy_token()

    current_user = manager.get_current_user(request("POST", "/execute"), type("Credentials", (), {"credentials": token})())

    assert current_user == {
        "user_id": "firebase-user-1",
        "username": "sotyhub:firebase-user-1",
        "email": None,
        "role": "user",
    }


def test_rejects_proxy_token_replayed_against_another_route():
    manager = auth.AuthManager(database_manager=None)
    token = proxy_token(path="/execute", method="POST")

    with pytest.raises(HTTPException) as error:
        manager.get_current_user(request("GET", "/execute/run-1"), type("Credentials", (), {"credentials": token})())

    assert error.value.status_code == 403
    assert error.value.detail == "BOFA proxy token scope mismatch"


def test_rejects_invalid_and_expired_proxy_tokens_as_unauthorized():
    manager = auth.AuthManager(database_manager=None)
    invalid = jwt.encode({"sub": "firebase-user-1"}, "wrong-secret", algorithm="HS256")
    expired = proxy_token(exp=datetime.now(timezone.utc) - timedelta(seconds=1))

    for token in (invalid, expired):
        with pytest.raises(HTTPException) as error:
            manager.verify_token(token)
        assert error.value.status_code == 401
