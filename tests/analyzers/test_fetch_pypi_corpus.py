from __future__ import annotations

import pytest

from tools.fetch_pypi_corpus import select_latest_pair


def _file(filename: str, package_type: str, *, yanked: bool = False):
    return {
        "filename": filename,
        "packagetype": package_type,
        "url": f"https://files.pythonhosted.org/packages/{filename}",
        "size": 123,
        "digests": {"sha256": "a" * 64},
        "yanked": yanked,
    }


def test_select_latest_verified_pure_pair() -> None:
    version, sdist, wheel = select_latest_pair(
        {
            "info": {"version": "1.2.3"},
            "urls": [
                _file("demo-1.2.3.tar.gz", "sdist"),
                _file("demo-1.2.3-py3-none-any.whl", "bdist_wheel"),
                _file("demo-1.2.3-cp311-cp311-win_amd64.whl", "bdist_wheel"),
            ],
        }
    )
    assert version == "1.2.3"
    assert sdist.filename.endswith(".tar.gz")
    assert wheel.filename.endswith("-py3-none-any.whl")


def test_yanked_or_native_only_release_is_rejected() -> None:
    with pytest.raises(ValueError):
        select_latest_pair(
            {
                "info": {"version": "1.2.3"},
                "urls": [
                    _file("demo-1.2.3.tar.gz", "sdist", yanked=True),
                    _file("demo-1.2.3-cp311-cp311-win_amd64.whl", "bdist_wheel"),
                ],
            }
        )
