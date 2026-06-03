from __future__ import annotations

import sys
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


def test_database_dirty_state_falls_back_to_change_count_baseline(monkeypatch):
    state = {"change_count": 7}
    fake_idaapi = types.SimpleNamespace(
        get_inf_structure=lambda: types.SimpleNamespace(
            database_change_count=state["change_count"]
        )
    )
    monkeypatch.delitem(sys.modules, "ida_ida", raising=False)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE", 7)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE_ERROR", None)

    assert ida_plugin._database_dirty_state() == (False, None)

    state["change_count"] = 8

    assert ida_plugin._database_dirty_state() == (True, None)


def test_database_dirty_state_unknown_without_change_count_baseline(monkeypatch):
    fake_idaapi = types.SimpleNamespace(
        get_inf_structure=lambda: types.SimpleNamespace(database_change_count=7)
    )
    monkeypatch.delitem(sys.modules, "ida_ida", raising=False)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE", None)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE_ERROR", None)

    dirty, error = ida_plugin._database_dirty_state()

    assert dirty is None
    assert "baseline is unavailable" in str(error)


def test_initialize_database_change_baseline_prefers_ida_ida(monkeypatch):
    fake_ida_ida = types.SimpleNamespace(inf_get_database_change_count=lambda: 42)
    monkeypatch.setitem(sys.modules, "ida_ida", fake_ida_ida)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", types.SimpleNamespace(), raising=False)

    baseline = ida_plugin._initialize_database_change_baseline()

    assert baseline == {"database_change_baseline": 42, "database_change_baseline_error": None}
    assert ida_plugin.DATABASE_CHANGE_COUNT_BASELINE == 42
    assert ida_plugin.DATABASE_CHANGE_COUNT_BASELINE_ERROR is None


def test_collect_database_info_uses_change_count_dirty_fallback(monkeypatch, tmp_path):
    saved_db = tmp_path / "sample.i64"
    saved_db.write_bytes(b"ida database")
    state = {"change_count": 10}
    fake_idaapi = types.SimpleNamespace(
        PATH_TYPE_IDB=1,
        get_path=lambda _path_type: str(saved_db),
        get_input_file_path=lambda: "input.exe",
        get_root_filename=lambda: "sample.exe",
        get_imagebase=lambda: 0x400000,
        get_inf_structure=lambda: types.SimpleNamespace(
            database_change_count=state["change_count"]
        ),
    )
    monkeypatch.delitem(sys.modules, "ida_ida", raising=False)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(ida_plugin, "idaapi", fake_idaapi, raising=False)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE", 10)
    monkeypatch.setattr(ida_plugin, "DATABASE_CHANGE_COUNT_BASELINE_ERROR", None)

    clean_info = ida_plugin._collect_database_info()

    assert clean_info["dirty"] is False
    assert clean_info["dirty_state_known"] is True
    assert clean_info["dirty_state_method"] == "database_change_count_baseline"
    assert clean_info["database_change_count"] == 10
    assert clean_info["database_change_baseline"] == 10
    assert clean_info["database_sha256"]

    state["change_count"] = 11

    dirty_info = ida_plugin._collect_database_info()

    assert dirty_info["dirty"] is True
    assert dirty_info["unsaved"] is True
    assert dirty_info["database_change_count"] == 11


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


def _all_supported_operations() -> list[dict]:
    return [
        {
            "op_id": "op-rename",
            "op": "rename",
            "ea": 0x1000,
            "source": "explicit_api",
            "new_name": "mcp_apply_e2e",
            "flags": 0,
        },
        {
            "op_id": "op-comment",
            "op": "comment",
            "ea": 0x1000,
            "source": "explicit_api",
            "text": "regular comment",
            "repeatable": False,
        },
        {
            "op_id": "op-function-comment",
            "op": "function_comment",
            "ea": 0x1000,
            "source": "explicit_api",
            "text": "function comment",
            "repeatable": False,
        },
        {
            "op_id": "op-patch-byte",
            "op": "patch_bytes",
            "ea": 0x1000,
            "source": "explicit_api",
            "old_bytes_hex": "55",
            "new_bytes_hex": "90",
        },
        {
            "op_id": "op-set-type",
            "op": "set_type",
            "ea": 0x1000,
            "source": "explicit_api",
            "decl": "int __cdecl mcp_apply_e2e(void);",
            "flags": 0,
        },
    ]


def test_apply_changes_applies_all_supported_operations(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    calls = []
    func = types.SimpleNamespace(start_ea=0x1000)

    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        types.SimpleNamespace(
            set_name=lambda ea, new_name, flags: calls.append(("rename", ea, new_name, flags))
            or True
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            set_cmt=lambda ea, text, repeatable: calls.append(
                ("comment", ea, text, repeatable)
            )
            or True,
            patch_bytes=lambda ea, data: calls.append(("patch_bytes", ea, data)) or True,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        types.SimpleNamespace(
            get_func=lambda ea: func if ea == 0x1000 else None,
            set_func_cmt=lambda function, text, repeatable: calls.append(
                ("function_comment", function.start_ea, text, repeatable)
            )
            or True,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "idc",
        types.SimpleNamespace(
            set_type=lambda ea, decl: calls.append(("set_type", ea, decl)) or True
        ),
    )

    result = ida_plugin.apply_changes_request(
        _apply_payload(operations=_all_supported_operations(), dry_run=False)
    )

    assert result["status"] == "ok"
    assert [item["op_id"] for item in result["applied"]] == [
        "op-rename",
        "op-comment",
        "op-function-comment",
        "op-patch-byte",
        "op-set-type",
    ]
    assert result["errors"] == []
    assert ("function_comment", 0x1000, "function comment", 0) in calls
    assert ("patch_bytes", 0x1000, b"\x90") in calls


def test_apply_changes_dry_run_does_not_call_write_apis(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)

    result = ida_plugin.apply_changes_request(
        _apply_payload(operations=_all_supported_operations(), dry_run=True)
    )

    assert result["status"] == "ok"
    assert result["applied"] == []
    assert result["errors"] == []
    assert len(result["skipped"]) == len(_all_supported_operations())


def test_apply_changes_patch_bytes_falls_back_to_patch_byte(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    calls = []
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            patch_bytes=lambda ea, data: calls.append(("patch_bytes", ea, data)) or False,
            patch_byte=lambda ea, value: calls.append(("patch_byte", ea, value)) or True,
        ),
    )

    result = ida_plugin.apply_changes_request(
        _apply_payload(
            operations=[
                {
                    "op_id": "op-patch-byte",
                    "op": "patch_bytes",
                    "ea": 0x1000,
                    "source": "explicit_api",
                    "old_bytes_hex": "558b",
                    "new_bytes_hex": "90cc",
                }
            ],
            dry_run=False,
        )
    )

    assert result["status"] == "ok"
    assert result["errors"] == []
    assert result["applied"][0]["op_id"] == "op-patch-byte"
    assert ("patch_bytes", 0x1000, b"\x90\xcc") in calls
    assert ("patch_byte", 0x1000, 0x90) in calls
    assert ("patch_byte", 0x1001, 0xCC) in calls


def test_apply_changes_non_dry_run_stops_after_first_error(monkeypatch):
    _clean_matching_metadata(monkeypatch)
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    calls = []

    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            set_cmt=lambda ea, text, repeatable: calls.append(
                ("comment", ea, text, repeatable)
            )
            or True,
            patch_bytes=lambda ea, data: calls.append(("patch_bytes", ea, data)) or True,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        types.SimpleNamespace(set_name=lambda ea, new_name, flags: False),
    )

    result = ida_plugin.apply_changes_request(
        _apply_payload(
            operations=[
                _all_supported_operations()[1],
                _all_supported_operations()[0],
                _all_supported_operations()[3],
            ],
            dry_run=False,
        )
    )

    assert result["status"] == "partial"
    assert [item["op_id"] for item in result["applied"]] == ["op-comment"]
    assert [item["op_id"] for item in result["errors"]] == ["op-rename"]
    assert not any(call[0] == "patch_bytes" for call in calls)


def test_inspect_address_data_returns_fake_ida_state(monkeypatch):
    monkeypatch.setattr(ida_plugin, "HAS_IDA", True)
    monkeypatch.setattr(
        ida_plugin,
        "_collect_database_info",
        lambda: {
            "dirty_state_known": True,
            "dirty": True,
            "unsaved": True,
            "database_identity_known": True,
            "database_sha256": "abc",
        },
    )
    monkeypatch.setattr(
        ida_plugin,
        "idc",
        types.SimpleNamespace(
            get_name=lambda ea: "mcp_apply_e2e" if ea == 0x401000 else "",
            get_bytes=lambda ea, byte_count: b"\x55\x8b\xec\x90"[:byte_count],
            get_type=lambda ea: "int __cdecl mcp_apply_e2e(void);",
            print_type=lambda ea, flags: "fallback",
            generate_disasm_line=lambda ea, flags: "push ebp",
        ),
        raising=False,
    )
    func = types.SimpleNamespace(start_ea=0x401000)
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            get_cmt=lambda ea, repeatable: "repeatable comment"
            if repeatable
            else "regular comment"
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        types.SimpleNamespace(
            get_func=lambda ea: func if ea == 0x401000 else None,
            get_func_cmt=lambda function, repeatable: "repeatable function comment"
            if repeatable
            else "function comment",
        ),
    )

    result = ida_plugin.inspect_address_data(address="0x401000", byte_count=4)

    assert result["found"] is True
    assert result["ea"] == 0x401000
    assert result["name"] == "mcp_apply_e2e"
    assert result["comment"] == "regular comment"
    assert result["repeatable_comment"] == "repeatable comment"
    assert result["function_comment"] == "function comment"
    assert result["repeatable_function_comment"] == "repeatable function comment"
    assert result["bytes_hex"] == "558bec90"
    assert result["type"] == "int __cdecl mcp_apply_e2e(void);"
    assert result["disassembly"] == "push ebp"
    assert result["dirty"] is True
    assert result["database_sha256"] == "abc"


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
