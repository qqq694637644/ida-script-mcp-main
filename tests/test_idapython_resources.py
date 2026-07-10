"""Contract tests for the packaged IDAPython skill resources."""

from __future__ import annotations

import os
import re
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


def test_idapython_is_a_single_entrypoint_progressive_disclosure_skill() -> None:
    root = _resource_root()
    skill_path = root / "SKILL.md"
    skill_text = skill_path.read_text(encoding="utf-8")

    assert skill_path.is_file()
    assert not (root / "skill.json").exists()
    assert not (root / "INDEX.md").exists()
    assert skill_text.startswith("---\nname: idapython\ndescription:")
    assert "# IDAPython for GPT-5.6 Sol" in skill_text
    assert "## Progressive disclosure" in skill_text
    assert len(skill_text.splitlines()) < 100

    required_terms = [
        "retrieveSkillContext",
        "searchSkillDocs",
        "readSkillContent",
        "listIdaInstances",
        "getIdaDatabaseInfo",
        "listIdaFunctions",
        "decompileIdaFunction",
        "getIdaXrefs",
        "executeIdapython",
        "selected_skills",
        "skill_id",
        "status",
        "stdout",
        "stderr",
        "result",
        "error",
        "ida_auto.auto_wait()",
        "64-bit",
    ]
    for term in required_terms:
        assert term in skill_text, term

    forbidden_terms = [
        "skill.json",
        "INDEX.md",
        "execute_idapython",
        "MCP tool",
        "MCP client",
        "@idasync",
        "execute_sync()",
        "int_convert MCP tool",
    ]
    for term in forbidden_terms:
        assert term not in skill_text, term

    referenced_paths = set(re.findall(r"`(docs/[^`]+\.(?:md|rst))`", skill_text))
    assert referenced_paths
    for relative_path in referenced_paths:
        assert (root / relative_path).is_file(), relative_path


def test_root_skill_matches_packaged_resource() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    root_skill = repo_root / "idapython" / "SKILL.md"
    packaged_skill = _resource_root() / "SKILL.md"

    assert root_skill.read_text(encoding="utf-8") == packaged_skill.read_text(encoding="utf-8")
    assert not (repo_root / "idapython" / "skill.json").exists()
    assert not (repo_root / "idapython" / "INDEX.md").exists()
