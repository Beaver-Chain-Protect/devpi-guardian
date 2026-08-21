from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile

import pytest

from devpi_guardian.analyzers import scan_install_surface


def _record_for(files: dict[str, bytes], rows: list[tuple[str, str, str]] | None = None) -> str:
    record = "demo-1.0.0.dist-info/RECORD"
    rows = rows if rows is not None else []
    for path, payload in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
        rows.append((path, f"sha256={digest}", str(len(payload))))
    rows.append((record, "", ""))
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue()


def _wheel(tmp_path, files: dict[str, bytes], record: str | bytes | None = None):
    path = tmp_path / "demo-1.0.0-py3-none-any.whl"
    entries = dict(files)
    if record is not None:
        entries["demo-1.0.0.dist-info/RECORD"] = (
            record.encode() if isinstance(record, str) else record
        )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(entries.items()):
            archive.writestr(name, payload)
    return path


def _rules(path):
    return [
        finding
        for finding in scan_install_surface(str(path))
        if finding.rule.startswith("wheel_record")
    ]


def test_valid_record_has_no_finding(tmp_path):
    files = {
        "demo/__init__.py": b"VALUE = 1\n",
        "demo-1.0.0.dist-info/METADATA": b"Name: demo\n",
    }
    artifact = _wheel(tmp_path, files, _record_for(files))
    assert _rules(artifact) == []


def test_missing_record_is_denied(tmp_path):
    artifact = _wheel(tmp_path, {"demo/__init__.py": b""})
    findings = _rules(artifact)
    assert len(findings) == 1
    assert findings[0].rule == "wheel_record_missing"
    assert findings[0].action == "DENY"


def test_multiple_records_are_denied(tmp_path):
    artifact = tmp_path / "multiple.whl"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("demo-1.0.0.dist-info/RECORD", "")
        archive.writestr("other-1.0.0.dist-info/RECORD", "")
    findings = _rules(artifact)
    assert findings and findings[0].rule == "wheel_record_integrity"


@pytest.mark.parametrize(
    "record",
    [
        "not,csv\n",
        '"unterminated,sha256=abc,1\n',
        "demo/__init__.py,sha256=abc\n",
        b"demo/__init__.py,sha256=abc,1\xff\n",
    ],
)
def test_malformed_record_is_denied(tmp_path, record):
    artifact = _wheel(tmp_path, {"demo/__init__.py": b""}, record)
    assert any(f.rule == "wheel_record_integrity" for f in _rules(artifact))


def test_hash_mismatch_and_size_mismatch_are_denied(tmp_path):
    files = {"demo/__init__.py": b"VALUE = 1\n"}
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"wrong").digest()).decode().rstrip("=")
    record = _record_for(files, [("demo/__init__.py", f"sha256={digest}", "999")])
    artifact = _wheel(tmp_path, files, record)
    findings = _rules(artifact)
    assert len(findings) >= 2
    assert any("demo/__init__.py" in f.file for f in findings)


def test_duplicate_and_unsafe_record_paths_are_denied(tmp_path):
    files = {"demo/__init__.py": b""}
    record = _record_for(
        files,
        [
            ("demo/__init__.py", "", "0"),
            ("../outside.py", "", ""),
            ("demo//__init__.py", "", ""),
        ],
    )
    artifact = _wheel(tmp_path, files, record)
    findings = _rules(artifact)
    assert len(findings) >= 3


def test_backslash_record_path_is_normalized(tmp_path):
    files = {"demo/__init__.py": b""}
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"").digest()).decode().rstrip("=")
    record = _record_for(
        {},
        [("demo\\__init__.py", f"sha256={digest}", "0")],
    )
    artifact = _wheel(tmp_path, files, record)
    assert _rules(artifact) == []


@pytest.mark.parametrize("hash_value", ["", "md5=abcd", "sha1=abcd", "wat=abcd", "sha256=###"])
def test_weak_unknown_or_malformed_hash_is_denied(tmp_path, hash_value):
    files = {"demo/__init__.py": b""}
    record = _record_for(files, [("demo/__init__.py", hash_value, "0")])
    artifact = _wheel(tmp_path, files, record)
    assert any(f.rule == "wheel_record_integrity" for f in _rules(artifact))


def test_noncanonical_hash_encoding_is_denied(tmp_path):
    files = {"demo/__init__.py": b""}
    encoded = base64.urlsafe_b64encode(hashlib.sha256(b"").digest()).decode().rstrip("=")
    record = _record_for(files, [("demo/__init__.py", f"sha256={encoded}A", "0")])
    artifact = _wheel(tmp_path, files, record)
    assert any(f.rule == "wheel_record_integrity" for f in _rules(artifact))


def test_unlisted_regular_file_and_unknown_row_are_denied(tmp_path):
    files = {"demo/__init__.py": b"", "demo/extra.py": b""}
    record = _record_for({"demo/__init__.py": b""}, [("does-not-exist.py", "", "")])
    artifact = _wheel(tmp_path, files, record)
    findings = _rules(artifact)
    assert len(findings) >= 2


def test_signature_siblings_may_be_unlisted(tmp_path):
    files = {
        "demo/__init__.py": b"",
        "demo-1.0.0.dist-info/RECORD.jws": b"signature",
    }
    artifact = _wheel(tmp_path, files, _record_for({"demo/__init__.py": b""}))
    assert _rules(artifact) == []


def test_sdist_is_unaffected(make_sdist):
    artifact = make_sdist({"demo/__init__.py": ""})
    assert not _rules(artifact)
