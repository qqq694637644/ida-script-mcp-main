"""Tests for packaged IDAPython skill metadata resources."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _resource_root() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ida_script_mcp"
        / "resources"
        / "idapython"
    )


def test_idapython_resource_has_skill_metadata() -> None:
    root = _resource_root()
    metadata = json.loads((root / "skill.json").read_text(encoding="utf-8"))

    assert metadata["skill_id"] == "idapython"
    assert metadata["entrypoint"] == "SKILL.md"
    assert metadata["index"] == "INDEX.md"
    assert "@idapython" in metadata["aliases"]
    assert "executeIdapython" in metadata["recommended_tools"]
    assert metadata["policy"]["allow_execute_idapython"] is True

    required_paths = ["SKILL.md", "INDEX.md", "docs/idautils.md", "docs/ida_hexrays.md"]
    for relative_path in required_paths:
        assert (root / relative_path).is_file(), relative_path

    for item in metadata["docs"]:
        assert (root / item["path"]).is_file(), item["path"]


def test_root_idapython_metadata_matches_packaged_resource() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    root_metadata = json.loads((repo_root / "idapython" / "skill.json").read_text(encoding="utf-8"))
    resource_metadata = json.loads((_resource_root() / "skill.json").read_text(encoding="utf-8"))

    assert root_metadata == resource_metadata
    assert (repo_root / "idapython" / "INDEX.md").read_text(encoding="utf-8") == (
        _resource_root() / "INDEX.md"
    ).read_text(encoding="utf-8")
