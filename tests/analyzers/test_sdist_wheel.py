from __future__ import annotations

from pathlib import Path

from devpi_guardian.analyzers import compare_sdist_wheel


def _rules(findings):
    return {item.rule for item in findings}


def test_missing_sdist_skips_comparison(make_wheel, tmp_path: Path) -> None:
    wheel = make_wheel({"demo/__init__.py": ""})
    assert compare_sdist_wheel(str(tmp_path / "missing.tar.gz"), str(wheel)) == []
    assert compare_sdist_wheel("", str(wheel)) == []


def test_mismatched_project_or_version_is_reviewed_before_diff(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n",
            "demo/__init__.py": "VALUE = 1\n",
        }
    )
    wheel = make_wheel(
        {
            "other/__init__.py": "VALUE = 1\n",
            "other-2.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: other\nVersion: 2.0.0\n"
            ),
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert [item.rule for item in findings] == ["artifact_identity_mismatch"]
    assert findings[0].action == "REVIEW"


def test_requires_dist_mismatch_is_reviewed(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "PKG-INFO": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\nRequires-Dist: safe-lib>=1\n"
            )
        }
    )
    wheel = make_wheel(
        {
            "demo-1.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\nRequires-Dist: evil-lib>=1\n"
            )
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    mismatch = [item for item in findings if item.rule == "requires_dist_mismatch"]
    assert len(mismatch) == 1
    assert mismatch[0].action == "REVIEW"


def test_requires_dist_semantic_normalization_avoids_false_mismatch(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "PKG-INFO": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                "Requires-Dist: Demo_Pkg[Beta, alpha] ( >= 1.0, < 2.0 ) ; "
                "python_version>='3.8' and extra==\"beta\"\n"
            )
        }
    )
    wheel = make_wheel(
        {
            "demo-1.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                "Requires-Dist: demo-pkg[alpha,beta]>=1.0,<2.0; "
                "python_version >= \"3.8\" and extra == 'beta'\n"
                "Requires-Dist: demo-pkg[alpha,beta]>=1.0,<2.0; "
                "python_version >= \"3.8\" and extra == 'beta'\n"
            )
        }
    )
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]


def test_requires_dist_direct_url_same_and_changed(make_sdist, make_wheel) -> None:
    def pair(sdist_url: str, wheel_url: str):
        sdist = make_sdist(
            {
                "PKG-INFO": (
                    "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                    "Requires-Dist: dep @  " + sdist_url + "  \n"
                )
            },
            name="direct-sdist.tar.gz",
        )
        wheel = make_wheel(
            {
                "demo-1.0.0.dist-info/METADATA": (
                    "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                    "Requires-Dist: dep @ " + wheel_url + "\n"
                )
            },
            name="direct-demo-1.0.0-py3-none-any.whl",
        )
        return sdist, wheel

    sdist, wheel = pair("https://example.test/dep-1.tar.gz", "https://example.test/dep-1.tar.gz")
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist, wheel = pair("https://example.test/dep-1.tar.gz", "https://example.test/dep-2.tar.gz")
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert len([item for item in findings if item.rule == "requires_dist_mismatch"]) == 1


def test_requires_dist_direct_url_internal_semicolon_preserves_marker(
    make_sdist, make_wheel
) -> None:
    sdist = make_sdist(
        {
            "PKG-INFO": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                "Requires-Dist: dep @ https://e.test/a;b ; python_version>='3.11'\n"
            )
        },
        name="semicolon-url.tar.gz",
    )
    wheel = make_wheel(
        {
            "demo-1.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                'Requires-Dist: dep @ https://e.test/a;b ; python_version >= "3.11"\n'
            )
        },
        name="semicolon-url-demo-1.0.0-py3-none-any.whl",
    )
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]


def test_requires_dist_direct_url_internal_semicolon_change_is_reviewed(
    make_sdist, make_wheel
) -> None:
    def pair(sdist_url: str, wheel_url: str):
        sdist = make_sdist(
            {
                "PKG-INFO": (
                    "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                    f"Requires-Dist: dep @ {sdist_url}\n"
                )
            },
            name="semicolon-only.tar.gz",
        )
        wheel = make_wheel(
            {
                "demo-1.0.0.dist-info/METADATA": (
                    "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
                    f"Requires-Dist: dep @ {wheel_url}\n"
                )
            },
            name="semicolon-only-demo-1.0.0-py3-none-any.whl",
        )
        return sdist, wheel

    sdist, wheel = pair("https://e.test/a;b", "https://e.test/a;b")
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist, wheel = pair("https://e.test/a;b", "https://e.test/a;c")
    assert [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]


def test_requires_dist_dynamic_semantics_for_25_and_26(make_sdist, make_wheel) -> None:
    def pair(version: str, dynamic: str, wheel_requirements: str):
        sdist = make_sdist(
            {
                "PKG-INFO": (
                    f"Metadata-Version: {version}\nName: demo\nVersion: 1.0.0\n"
                    f"{dynamic}Requires-Dist: base>=1\n"
                )
            },
            name=f"dynamic-{version}.tar.gz",
        )
        wheel = make_wheel(
            {
                "demo-1.0.0.dist-info/METADATA": (
                    f"Metadata-Version: {version}\nName: demo\nVersion: 1.0.0\n{wheel_requirements}"
                )
            },
            name=f"dynamic-{version}-demo-1.0.0-py3-none-any.whl",
        )
        return sdist, wheel

    sdist, wheel = pair("2.5", "Dynamic: Requires-Dist\n", "Requires-Dist: changed>=1\n")
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist, wheel = pair(
        "2.6", "Dynamic: Requires-Dist\n", "Requires-Dist: base>=1\nRequires-Dist: added>=1\n"
    )
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist, wheel = pair("2.6", "Dynamic: Requires-Dist\n", "Requires-Dist: changed>=1\n")
    assert (
        len(
            [
                item
                for item in compare_sdist_wheel(str(sdist), str(wheel))
                if item.rule == "requires_dist_mismatch"
            ]
        )
        == 1
    )


def test_requires_dist_pre_22_and_missing_metadata_are_skipped(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {"PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\nRequires-Dist: old\n"},
        name="pre22.tar.gz",
    )
    wheel = make_wheel(
        {
            "demo-1.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\nRequires-Dist: new\n"
            )
        },
        name="pre22-demo-1.0.0-py3-none-any.whl",
    )
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist = make_sdist({"demo/__init__.py": ""}, name="missing-meta.tar.gz")
    wheel = make_wheel({"demo/__init__.py": ""}, name="missing-meta-demo-1.0.0-py3-none-any.whl")
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]


def test_requires_dist_malformed_values_are_stable_and_safe(make_sdist, make_wheel) -> None:
    def pair(sdist_value: str, wheel_value: str):
        sdist = make_sdist(
            {
                "PKG-INFO": "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\nRequires-Dist: "
                + sdist_value
                + "\n"
            },
            name="malformed.tar.gz",
        )
        wheel = make_wheel(
            {
                "demo-1.0.0.dist-info/METADATA": (
                    "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\nRequires-Dist: "
                )
                + wheel_value
                + "\n"
            },
            name="malformed-demo-1.0.0-py3-none-any.whl",
        )
        return sdist, wheel

    sdist, wheel = pair("not a valid requirement ???", "not a valid requirement ???")
    assert not [
        item
        for item in compare_sdist_wheel(str(sdist), str(wheel))
        if item.rule == "requires_dist_mismatch"
    ]
    sdist, wheel = pair("not a valid requirement ???", "not a valid requirement !!!")
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert len([item for item in findings if item.rule == "requires_dist_mismatch"]) == 1


def test_requires_dist_evidence_is_bounded_and_deterministic(make_sdist, make_wheel) -> None:
    sdist_requirements = "".join(f"Requires-Dist: old-{index}\n" for index in range(20))
    wheel_requirements = "".join(f"Requires-Dist: new-{index}\n" for index in range(20))
    sdist = make_sdist(
        {"PKG-INFO": "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n" + sdist_requirements},
        name="many.tar.gz",
    )
    wheel = make_wheel(
        {
            "demo-1.0.0.dist-info/METADATA": "Metadata-Version: 2.5\nName: demo\nVersion: 1.0.0\n"
            + wheel_requirements
        },
        name="many-demo-1.0.0-py3-none-any.whl",
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    mismatch = [item for item in findings if item.rule == "requires_dist_mismatch"]
    assert len(mismatch) == 1
    assert len(mismatch[0].snippet) <= 200
    assert "+15개" in mismatch[0].snippet


def test_project_name_separator_normalization_avoids_false_mismatch(make_sdist, make_wheel) -> None:
    source = "VALUE = 1\n"
    sdist = make_sdist(
        {
            "PKG-INFO": "Metadata-Version: 2.1\nName: Demo_Pkg\nVersion: 1.0.0\n",
            "demo_pkg/__init__.py": source,
        }
    )
    wheel = make_wheel(
        {
            "demo_pkg/__init__.py": source,
            "demo_pkg-1.0.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\n"
            ),
        }
    )
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_native_platform_wheel_is_reported_as_unsupported(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo-1.0.0.dist-info/WHEEL": (
                "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp311-cp311-win_amd64\n"
            ),
        },
        name="demo-1.0.0-cp311-cp311-win_amd64.whl",
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert [item.rule for item in findings] == ["unsupported_wheel_scope"]
    assert findings[0].action == "REVIEW"


def test_wheel_with_py2_and_py3_tags_is_supported(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo-1.0.0.dist-info/WHEEL": (
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n"
            ),
        }
    )
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_comments_whitespace_and_docstrings_are_normalized(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "demo/core.py": (
                "'''sdist docs'''\ndef add(a, b):\n    '''function docs'''\n    return a + b\n"
            )
        }
    )
    wheel = make_wheel(
        {
            "demo/core.py": (
                "'''wheel docs changed'''\n\n"
                "# comment only\n"
                "def add(a,b):\n"
                "    '''different docs'''\n"
                "    return a+b\n"
            )
        }
    )
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_setuptools_scm_generated_commit_id_is_normalized(make_sdist, make_wheel) -> None:
    common = "# file generated by setuptools-scm\n__version__ = version = '2.3.0'\n"
    sdist = make_sdist({"src/demo/_version.py": common + "__commit_id__ = commit_id = 'g123'\n"})
    wheel = make_wheel({"demo/_version.py": common + "__commit_id__ = commit_id = None\n"})
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_src_layout_is_normalized_against_wheel_root(make_sdist, make_wheel) -> None:
    source = "def add(a, b):\n    return a + b\n"
    sdist = make_sdist(
        {
            "pyproject.toml": (
                "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n"
            ),
            "src/demo/core.py": source,
        }
    )
    wheel = make_wheel({"demo/core.py": source})
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_equivalent_entry_point_formats_do_not_mismatch(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "pyproject.toml": (
                "[project]\nname = 'demo'\nversion = '1.0.0'\n"
                "[project.scripts]\ndemo = 'demo.cli:main'\n"
            ),
            "src/demo/cli.py": "def main(): return 0\n",
        }
    )
    wheel = make_wheel(
        {
            "demo/cli.py": "def main(): return 0\n",
            "demo-1.0.0.dist-info/entry_points.txt": ("[console_scripts]\ndemo = demo.cli:main\n"),
        }
    )
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_wheel_only_dangerous_python_is_denied(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo/update.py": "import subprocess\nsubprocess.run(['echo', 'blocked'])\n",
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert "wheel_only_risky_python" in _rules(findings)
    assert any(item.action == "DENY" for item in findings)


def test_wheel_only_literal_dynamic_import_keeps_dangerous_module_handling(
    make_sdist, make_wheel
) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo/lazy.py": (
                "import importlib\n"
                "importlib.import_module('pydantic.fields')\n"
                "importlib.import_module('requests')\n"
            ),
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    risky = [item for item in findings if item.rule == "wheel_only_risky_python"]
    assert len(risky) == 1
    assert risky[0].line == 3


def test_wheel_only_credential_network_flow_is_denied(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo/update.py": (
                "import os\nimport requests\n"
                "secret = os.getenv('GITHUB_TOKEN')\n"
                "requests.post('http://127.0.0.1:1/', data=secret)\n"
            ),
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert "wheel_only_credential_network" in _rules(findings)
    assert any(item.source and item.sink == "requests.post" for item in findings)


def test_wheel_only_executable_pth_is_denied(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel(
        {
            "demo/__init__.py": "",
            "demo.pth": "import os; os.system('blocked')\n",
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert "wheel_only_executable_pth" in _rules(findings)


def test_entry_point_mismatch_is_review(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "setup.cfg": ("[options.entry_points]\nconsole_scripts =\n    demo = demo.cli:main\n"),
            "demo/cli.py": "def main(): return 0\n",
        }
    )
    wheel = make_wheel(
        {
            "demo/cli.py": "def main(): return 0\n",
            "demo-1.0.0.dist-info/entry_points.txt": ("[console_scripts]\nother = demo.cli:main\n"),
        }
    )
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    mismatch = [item for item in findings if item.rule == "entry_point_mismatch"]
    assert mismatch and mismatch[0].action == "REVIEW"


def test_nested_example_setup_py_does_not_define_package_entry_points(
    make_sdist, make_wheel
) -> None:
    sdist = make_sdist(
        {
            "demo/__init__.py": "",
            "docs/example/setup.py": (
                "from setuptools import setup\n"
                "setup(entry_points={'console_scripts': "
                "['sample = example:main']})\n"
            ),
        }
    )
    wheel = make_wheel({"demo/__init__.py": ""})
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_metadata_only_differences_are_ignored(make_sdist, make_wheel) -> None:
    sdist = make_sdist(
        {
            "demo/__init__.py": "VALUE = 1\n",
            "demo.egg-info/PKG-INFO": "sdist metadata",
        }
    )
    wheel = make_wheel(
        {
            "demo/__init__.py": "VALUE = 1\n",
            "demo-1.0.0.dist-info/METADATA": "wheel metadata",
            "demo-1.0.0.dist-info/RECORD": "different hashes",
        }
    )
    assert compare_sdist_wheel(str(sdist), str(wheel)) == []


def test_unparseable_python_is_review_not_exception(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/core.py": "def broken(:\n"})
    wheel = make_wheel({"demo/core.py": "def broken(:\n"})
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    assert "ast_parse_failed" in _rules(findings)
    assert all(item.action == "REVIEW" for item in findings)


def test_meaningful_python_ast_difference_is_review(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/core.py": "VALUE = 1\n"})
    wheel = make_wheel({"demo/core.py": "VALUE = 2\n"})
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    mismatch = [item for item in findings if item.rule == "python_ast_mismatch"]
    assert mismatch and mismatch[0].action == "REVIEW"


def test_wheel_only_native_binary_is_review(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel({"demo/__init__.py": "", "demo/native.so": b"not-real"})
    findings = compare_sdist_wheel(str(sdist), str(wheel))
    native = [item for item in findings if item.rule == "wheel_only_native"]
    assert native and native[0].action == "REVIEW"
