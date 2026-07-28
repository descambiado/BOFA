#!/usr/bin/env python3
"""Smoke verification for BOFA authentication and local runtime security."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

from fastapi import HTTPException

_ROOT = Path(__file__).resolve().parent.parent
_VERIFY_ROOT = _ROOT / "data" / ".verify_auth_security"
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)

os.environ.setdefault("BOFA_APP_ROOT", str(_VERIFY_ROOT))
os.environ.setdefault("BOFA_DB_PATH", str(_VERIFY_ROOT / "bootstrap.db"))
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(48))

if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.auth import AuthManager
from api.database import DatabaseManager
from api.passwords import PASSWORD_SCHEME
from api.script_executor import ScriptExecutor


def _make_database() -> DatabaseManager:
    return DatabaseManager(str(_VERIFY_ROOT / f"auth_{uuid.uuid4().hex}.db"))


def _check_initial_admin_bootstrap() -> None:
    db = _make_database()
    auth = AuthManager(db)
    password = f"verify-{uuid.uuid4().hex}"
    user_id = auth.bootstrap_admin("owner", "owner@example.com", password)
    assert user_id
    assert auth.bootstrap_admin("second", "second@example.com", f"verify-{uuid.uuid4().hex}") is None

    user = db.get_user_by_username("owner")
    assert user and user["role"] == "admin"
    assert user["password_hash"].startswith(f"{PASSWORD_SCHEME}$")
    assert auth.verify_password(password, user["password_hash"])
    assert not auth.verify_password(f"wrong-{uuid.uuid4().hex}", user["password_hash"])


def _check_legacy_hash_migration() -> None:
    db = _make_database()
    password = f"legacy-{uuid.uuid4().hex}"
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    user_id = db.create_user("legacy", "legacy@example.com", legacy_hash)
    assert user_id

    auth = AuthManager(db)
    user = auth.authenticate_user("legacy", password)
    assert user
    migrated = db.get_user_by_username("legacy")
    assert migrated and migrated["password_hash"].startswith(f"{PASSWORD_SCHEME}$")


def _check_tokens() -> None:
    db = _make_database()
    auth = AuthManager(db)
    payload = {"user_id": 1, "username": "owner", "email": "owner@example.com", "role": "admin"}
    token = auth.create_access_token(payload)
    assert auth.verify_token(token)["username"] == "owner"

    try:
        auth.verify_token(f"{token}tampered")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("Tampered JWT was accepted")


def _check_legacy_default_retirement() -> None:
    db = _make_database()
    known_hash = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
    assert db.create_user("admin", "admin@example.com", known_hash, "admin")
    db.retire_insecure_default_admin()
    assert db.get_user_by_username("admin") is None
    assert db.count_active_users() == 0


def _check_portable_sandbox_paths() -> None:
    db = _make_database()
    temp_root = _VERIFY_ROOT / f"sandboxes_{uuid.uuid4().hex}"
    executor = ScriptExecutor(db, scripts_dir=str(_ROOT / "scripts"), temp_dir=str(temp_root))
    sandbox = executor.create_sandbox_environment("portable")
    assert sandbox == temp_root / "sandbox_portable"
    assert (sandbox / "input").is_dir()
    executor.cleanup_sandbox("portable")


def _check_api_imports_without_external_services() -> None:
    runtime_root = _VERIFY_ROOT / f"api_{uuid.uuid4().hex}"
    env = os.environ.copy()
    env.update(
        {
            "BOFA_APP_ROOT": str(runtime_root),
            "BOFA_DB_PATH": str(runtime_root / "bofa.db"),
            "BOFA_SCRIPTS_DIR": str(_ROOT / "scripts"),
            "JWT_SECRET": secrets.token_urlsafe(48),
            "DOCKER_HOST": "tcp://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
        }
    )
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(_ROOT / 'api')!r}); "
        "import main; "
        "assert '*' not in main.ALLOWED_ORIGINS; "
        "assert 'role' not in main.RegisterRequest.model_fields; "
        "assert main.db.count_active_users() == 0; "
        "assert main.script_executor.temp_dir == main.TEMP_DIR; "
        "print(main.app.title)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def main() -> int:
    checks = [
        ("initial admin bootstrap is single-use and PBKDF2-backed", _check_initial_admin_bootstrap),
        ("legacy SHA-256 hashes migrate after successful login", _check_legacy_hash_migration),
        ("JWT verification rejects tampering", _check_tokens),
        ("known public bootstrap account is retired", _check_legacy_default_retirement),
        ("script sandboxes use portable configured paths", _check_portable_sandbox_paths),
        ("API imports securely without Docker or Unix-only modules", _check_api_imports_without_external_services),
    ]

    print("BOFA Authentication Security Verification")
    print("=" * 44)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
