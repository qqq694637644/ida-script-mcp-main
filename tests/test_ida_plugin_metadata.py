from __future__ import annotations

import types

from ida_script_mcp import ida_plugin


def test_collect_database_info_uses_saved_idb_path_not_input_path(monkeypatch, tmp_path):
    saved_db = tmp_path / "sample.i64"
    input_file = tmp_path / "sample.exe"
    saved_db.write_bytes(b"ida database")
    input_file.write_bytes(b"input")

    fake_idaapi = types.SimpleNamespace(
        PATH_TYPE_IDB=1,
        get_path=lambda path_type: str(saved_db) if path_type == 1 else None,
        get_input_file_path=lambda: str(input_file),
        is_database_modified=lambda: False,
        get_root_filename=lambda: "sample.exe",
        get_imagebase=lambda: 0x400000,
        get_inf_structure=lambda: None,
    )
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)

    info = ida_plugin._collect_database_info()

    assert info["database_path"] == str(saved_db)
    assert info["input_file_path"] == str(input_file)
    assert info["database_path"] != info["input_file_path"]
    assert info["database_sha256"]
    assert info["dirty"] is False
    assert info["dirty_state_known"] is True


def test_collect_database_info_marks_dirty_unknown_on_api_failure(monkeypatch, tmp_path):
    saved_db = tmp_path / "sample.i64"
    saved_db.write_bytes(b"ida database")

    def dirty_failure():
        raise RuntimeError("cannot tell")

    fake_idaapi = types.SimpleNamespace(
        PATH_TYPE_IDB=1,
        get_path=lambda _path_type: str(saved_db),
        get_input_file_path=lambda: "input.exe",
        is_database_modified=dirty_failure,
        get_root_filename=lambda: "sample.exe",
        get_imagebase=lambda: 0x400000,
        get_inf_structure=lambda: None,
    )
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)

    info = ida_plugin._collect_database_info()

    assert info["dirty"] is None
    assert info["unsaved"] is None
    assert info["dirty_state_known"] is False
    assert "cannot tell" in info["dirty_error"]


def test_collect_database_info_marks_database_hash_failure_unknown(monkeypatch, tmp_path):
    saved_db = tmp_path / "sample.i64"
    saved_db.write_bytes(b"ida database")
    fake_idaapi = types.SimpleNamespace(
        PATH_TYPE_IDB=1,
        get_path=lambda _path_type: str(saved_db),
        get_input_file_path=lambda: "input.exe",
        is_database_modified=lambda: False,
        get_root_filename=lambda: "sample.exe",
        get_imagebase=lambda: 0x400000,
        get_inf_structure=lambda: None,
    )
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)
    monkeypatch.setattr(ida_plugin, "_sha256_file", lambda _path: None)

    info = ida_plugin._collect_database_info()

    assert info["database_identity_known"] is False
    assert "failed to compute SHA-256" in info["database_identity_error"]


def _apply_payload(
    database_sha256: str = "abc",
    *,
    operations: list[dict] | None = None,
    dry_run: bool = True,
) -> dict:
    return {
        "schema_version": 1,
        "job_id": "job-1",
        "database_fingerprint": {"database_sha256": database_sha256},
        "operations": operations or [],
        "dry_run": dry_run,
    }


def test_apply_changes_rejects_dirty_gui_before_fingerprint(monkeypatch):
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": True,
            "dirty": True,
            "unsaved": True,
            "database_sha256": "abc",
        },
    )

    result = ida_plugin.apply_changes_request(_apply_payload("abc"))

    assert result["status"] == "rejected"
    assert "unsaved changes" in result["message"]


def test_apply_changes_rejects_unknown_dirty_state_before_fingerprint(monkeypatch):
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": False,
            "dirty": None,
            "unsaved": None,
            "database_sha256": "abc",
        },
    )

    result = ida_plugin.apply_changes_request(_apply_payload("abc"))

    assert result["status"] == "rejected"
    assert "dirty state is unknown" in result["message"]


def test_apply_changes_allows_clean_dry_run_with_matching_fingerprint(monkeypatch):
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": True,
            "dirty": False,
            "unsaved": False,
            "database_sha256": "abc",
        },
    )

    result = ida_plugin.apply_changes_request(_apply_payload("abc"))

    assert result["status"] == "ok"
    assert result["dry_run"] is True


def test_apply_changes_rejects_missing_database_identity(monkeypatch):
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": True,
            "dirty": False,
            "unsaved": False,
            "database_identity_known": False,
        },
    )

    result = ida_plugin.apply_changes_request(_apply_payload("abc"))

    assert result["status"] == "rejected"
    assert "SHA-256 is unavailable" in result["message"]


def _clean_matching_metadata(monkeypatch):
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": True,
            "dirty": False,
            "unsaved": False,
            "database_identity_known": True,
            "database_sha256": "abc",
        },
    )


def test_apply_changes_rename_missing_gui_api_returns_operation_error(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", False)
    payload = _apply_payload(
        operations=[
            {
                "op_id": "op-1",
                "op": "rename",
                "ea": 0x1000,
                "source": "explicit_api",
                "new_name": "main",
            }
        ],
        dry_run=False,
    )

    result = ida_plugin.apply_changes_request(payload)

    assert result["status"] == "error"
    assert result["applied"] == []
    assert result["errors"][0]["status"] == "error"
    assert "IDA runtime is unavailable" in result["errors"][0]["message"]


def test_apply_changes_set_type_missing_gui_api_returns_operation_error(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", False)
    payload = _apply_payload(
        operations=[
            {
                "op_id": "op-1",
                "op": "set_type",
                "ea": 0x1000,
                "source": "explicit_api",
                "decl": "int main(void);",
            }
        ],
        dry_run=False,
    )

    result = ida_plugin.apply_changes_request(payload)

    assert result["status"] == "error"
    assert result["applied"] == []
    assert result["errors"][0]["status"] == "error"
    assert "IDA runtime is unavailable" in result["errors"][0]["message"]


def test_apply_changes_dry_run_skips_without_gui_api(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", False)
    payload = _apply_payload(
        operations=[
            {
                "op_id": "op-1",
                "op": "rename",
                "ea": 0x1000,
                "source": "explicit_api",
                "new_name": "main",
            }
        ],
        dry_run=True,
    )

    result = ida_plugin.apply_changes_request(payload)

    assert result["status"] == "ok"
    assert result["applied"] == []
    assert result["errors"] == []
    assert result["skipped"][0]["status"] == "skipped"
