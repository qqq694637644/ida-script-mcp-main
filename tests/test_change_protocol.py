from __future__ import annotations

import pytest
from pydantic import ValidationError

from ida_script_mcp.change_protocol import (
    ChangeSet,
    DatabaseFingerprint,
    RenameChange,
    fingerprint_matches,
)
from ida_script_mcp.protocol import ExecuteResult


def test_discriminated_union_and_json_serialization():
    change_set = ChangeSet(
        job_id="job-1",
        database_fingerprint=DatabaseFingerprint(input_sha256="a"),
        operations=[
            RenameChange(op_id="op-1", ea=0x401000, new_name="main", source="explicit_api")
        ],
    )

    parsed = ChangeSet.model_validate_json(change_set.model_dump_json())

    assert parsed.operations[0].op == "rename"
    assert parsed.operations[0].ea == 0x401000


def test_unknown_change_fields_rejected():
    with pytest.raises(ValidationError):
        ChangeSet.model_validate(
            {
                "job_id": "job-1",
                "database_fingerprint": {},
                "operations": [
                    {
                        "op_id": "op-1",
                        "op": "rename",
                        "ea": 1,
                        "new_name": "x",
                        "source": "explicit_api",
                        "extra": True,
                    }
                ],
            }
        )


def test_fingerprint_matching_requires_strong_identity():
    assert fingerprint_matches(
        DatabaseFingerprint(input_sha256="a"), DatabaseFingerprint(input_sha256="a")
    )
    assert fingerprint_matches(
        DatabaseFingerprint(input_md5="m", root_filename="x", imagebase=1),
        DatabaseFingerprint(input_md5="m", root_filename="x", imagebase=1),
    )
    assert fingerprint_matches(
        DatabaseFingerprint(database_sha256="abc"), DatabaseFingerprint(database_sha256="abc")
    )
    assert not fingerprint_matches(
        DatabaseFingerprint(database_path="same"), DatabaseFingerprint(database_path="same")
    )


def test_database_hash_is_authoritative_for_replay_identity():
    assert not fingerprint_matches(
        DatabaseFingerprint(input_sha256="same-input", database_sha256="old-idb"),
        DatabaseFingerprint(input_sha256="same-input", database_sha256="new-idb"),
    )
    assert not fingerprint_matches(
        DatabaseFingerprint(input_sha256="same-input", database_sha256="old-idb"),
        DatabaseFingerprint(input_sha256="same-input"),
    )


def test_execute_result_accepts_worker_status_and_rejects_old_plugin_timeout():
    ExecuteResult(status="worker_start_error")
    with pytest.raises(ValidationError):
        ExecuteResult(status="plugin_response_timeout")
