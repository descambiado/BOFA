#!/usr/bin/env python3
"""
BOFA runtime catalog verification.

Checks that the runtime script catalog, API serialization contract and
frontend module coverage stay aligned around a single source of truth.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

try:
    import yaml
except ModuleNotFoundError:
    yaml = SimpleNamespace(safe_load=lambda *args, **kwargs: {})

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_VERIFY_ROOT = _ROOT / "data" / ".verify_runtime_catalog"
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("BOFA_DB_PATH", str(_VERIFY_ROOT / "bootstrap.db"))


def _load_main_catalog_helpers() -> dict[str, Any]:
    source_path = _ROOT / "api" / "main.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename="api/main.py")
    wanted_functions = {
        "load_script_configs",
        "_module_metadata",
        "_resolve_script_code_path",
        "_serialize_script_config",
    }
    wanted_variables = {"SCRIPT_CONFIGS", "RECENT_SCRIPT_DATES", "MODULE_METADATA"}
    namespace: dict[str, Any] = {
        "Any": Any,
        "Dict": Dict,
        "Path": Path,
        "SCRIPTS_DIR": _ROOT / "scripts",
        "logger": SimpleNamespace(warning=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None),
        "yaml": yaml,
    }

    for node in tree.body:
        should_exec = False
        if isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
            should_exec = True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted_variables:
                    should_exec = True
                    break
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in wanted_variables:
            should_exec = True

        if should_exec:
            module = ast.Module(body=[node], type_ignores=[])
            code = compile(module, filename="api/main.py", mode="exec")
            exec(code, namespace)

    missing = (wanted_functions | wanted_variables) - set(namespace.keys())
    if missing:
        raise RuntimeError(f"Missing main.py helpers: {', '.join(sorted(missing))}")
    return namespace


_MAIN_HELPERS = _load_main_catalog_helpers()
MODULE_METADATA = _MAIN_HELPERS["MODULE_METADATA"]
RECENT_SCRIPT_DATES = _MAIN_HELPERS["RECENT_SCRIPT_DATES"]
SCRIPT_CONFIGS = _MAIN_HELPERS["SCRIPT_CONFIGS"]
_module_metadata = _MAIN_HELPERS["_module_metadata"]
_serialize_script_config = _MAIN_HELPERS["_serialize_script_config"]


def _load_frontend_module_icon_keys() -> set[str]:
    source = (_ROOT / "src" / "pages" / "Scripts.tsx").read_text(encoding="utf-8")
    match = re.search(r"const moduleIcons\b[\s\S]*?=\s*\{(?P<body>.*?)\n\};", source, re.DOTALL)
    if not match:
        return set()

    keys: set[str] = set()
    for line in match.group("body").splitlines():
        icon_match = re.match(r"\s*([a-z_]+):\s*[A-Za-z0-9_]+,?\s*$", line)
        if icon_match:
            keys.add(icon_match.group(1))
    return keys


def _check_module_metadata_coverage() -> bool:
    runtime_modules = set(SCRIPT_CONFIGS.keys())
    missing_metadata = sorted(runtime_modules - set(MODULE_METADATA.keys()))
    if missing_metadata:
        print(f"Missing module metadata: {', '.join(missing_metadata)}")
        return False

    return all(_module_metadata(module_id).get("name") and _module_metadata(module_id).get("description") for module_id in runtime_modules)


def _check_module_summary_counts() -> bool:
    total_scripts = 0
    for module_id, scripts in SCRIPT_CONFIGS.items():
        if not isinstance(scripts, list):
            print(f"Module {module_id} does not serialize to a script list")
            return False
        recent_count = sum(1 for script in scripts if script.get("last_updated") in RECENT_SCRIPT_DATES)
        if recent_count < 0:
            return False
        total_scripts += len(scripts)
    return total_scripts > 0


def _check_catalog_serialization() -> bool:
    seen_ids: set[tuple[str, str]] = set()

    for module_id, scripts in SCRIPT_CONFIGS.items():
        module_name = _module_metadata(module_id)["name"]
        for script_config in scripts:
            serialized = _serialize_script_config(module_id, script_config)
            script_key = (module_id, serialized["id"])
            yaml_path = Path(serialized["file_path_yaml"])
            py_path = Path(serialized["file_path_py"]) if serialized.get("file_path_py") else None

            if script_key in seen_ids:
                print(f"Duplicate serialized id detected: {module_id}/{serialized['id']}")
                return False
            seen_ids.add(script_key)

            if serialized.get("module_id") != module_id:
                print(f"Serialized module_id mismatch for {module_id}/{serialized['id']}")
                return False
            if serialized.get("module_name") != module_name:
                print(f"Serialized module_name mismatch for {module_id}/{serialized['id']}")
                return False
            if not serialized.get("display_name"):
                print(f"Serialized display_name missing for {module_id}/{serialized['id']}")
                return False
            if not yaml_path.exists():
                print(f"Serialized YAML path missing for {module_id}/{serialized['id']}: {yaml_path}")
                return False

            has_code = bool(serialized.get("has_code"))
            if has_code != bool(py_path and py_path.exists()):
                print(f"Serialized code availability mismatch for {module_id}/{serialized['id']}")
                return False

            expected_recent = script_config.get("last_updated") in RECENT_SCRIPT_DATES
            if serialized.get("is_recent") != expected_recent:
                print(f"Recent flag mismatch for {module_id}/{serialized['id']}")
                return False

    return True


def _check_frontend_module_coverage() -> bool:
    frontend_modules = _load_frontend_module_icon_keys()
    runtime_modules = set(SCRIPT_CONFIGS.keys())
    missing = sorted(runtime_modules - frontend_modules)
    if missing:
        print(f"Scripts page is missing runtime module icons for: {', '.join(missing)}")
        return False
    return True


def _check_legacy_catalog_removed() -> bool:
    legacy_path = _ROOT / "src" / "utils" / "scriptLoader.ts"
    return not legacy_path.exists()


def main() -> None:
    module_count = len(SCRIPT_CONFIGS)
    script_count = sum(len(scripts) for scripts in SCRIPT_CONFIGS.values())
    checks = [
        ("runtime modules all have API metadata", _check_module_metadata_coverage()),
        ("runtime modules expose consistent script inventories", _check_module_summary_counts()),
        ("catalog serialization matches runtime files and recent flags", _check_catalog_serialization()),
        ("scripts UI covers every runtime module", _check_frontend_module_coverage()),
        ("legacy client-side script catalog has been removed", _check_legacy_catalog_removed()),
    ]

    failed = [name for name, ok in checks if not ok]

    print("BOFA Runtime Catalog Verification")
    print("=" * 38)
    print(f"Modules: {module_count}")
    print(f"Scripts: {script_count}")
    for name, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}")

    if failed:
        print()
        print("Failed checks:")
        for name in failed:
            print(f"- {name}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
