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
