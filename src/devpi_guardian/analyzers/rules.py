"""Rule identifiers, default actions, and Korean operator messages."""

from __future__ import annotations

from dataclasses import dataclass

from .types import Action

RULESET_VERSION = "1.3.0"


@dataclass(frozen=True)
class Rule:
    action: Action
    message: str


RULES: dict[str, Rule] = {
    # F8: installation-surface rules in SPEC-F8-F9 section 3.1 plus wheel RECORD integrity.
    "setup_py_process": Rule("DENY", "setup.py가 설치 중 외부 프로세스를 실행합니다."),
    "setup_py_network": Rule("DENY", "setup.py가 설치 중 네트워크 통신을 시도합니다."),
    "setup_py_cmdclass": Rule("DENY", "setup.py가 설치 명령을 사용자 정의 코드로 재정의합니다."),
    "setup_py_file_write": Rule("REVIEW", "setup.py가 설치 중 파일을 쓰거나 이동합니다."),
    "nonstandard_build_backend": Rule("REVIEW", "표준 허용 목록에 없는 빌드 백엔드를 사용합니다."),
    "unknown_build_requirement": Rule(
        "REVIEW", "알려진 빌드 도구 목록에 없는 빌드 의존성이 있습니다."
    ),
    "setup_cfg_entry_points": Rule("REVIEW", "setup.cfg가 설치 후 실행 진입점을 등록합니다."),
    "executable_pth": Rule("DENY", ".pth 파일이 Python 시작 시 코드를 실행합니다."),
    "customize_module": Rule(
        "DENY",
        "Python 시작 시 자동으로 불리는 customize 모듈이 포함되어 있습니다.",
    ),
    "init_top_level_side_effect": Rule("REVIEW", "패키지를 import할 때 최상위 코드가 실행됩니다."),
    "entry_point": Rule("REVIEW", "패키지가 console 또는 GUI 실행 명령을 등록합니다."),
    "native_or_executable": Rule(
        "REVIEW", "네이티브 바이너리 또는 실행 권한 파일이 포함되어 있습니다."
    ),
    "archive_unsafe_member": Rule("DENY", "아카이브에 경로 이탈·링크·특수 파일 멤버가 있습니다."),
    "archive_bomb": Rule("DENY", "아카이브가 크기·압축률·파일 수 안전 한도를 초과합니다."),
    "wheel_record_missing": Rule("DENY", "wheel에 정확히 하나의 dist-info/RECORD가 없습니다."),
    "wheel_record_integrity": Rule(
        "DENY", "wheel의 dist-info/RECORD가 파일 목록·해시·크기와 일치하지 않습니다."
    ),
    # F9: the six sdist/wheel mismatch rules in section 4.4.
    "wheel_only_risky_python": Rule(
        "DENY",
        "sdist에는 없고 wheel에만 있는 Python 파일에 위험 동작이 있습니다.",
    ),
    "wheel_only_executable_pth": Rule(
        "DENY", "sdist에는 없고 wheel에만 실행 가능한 .pth 파일이 있습니다."
    ),
    "wheel_only_credential_network": Rule(
        "DENY",
        "wheel 전용 코드가 credential을 읽어 외부 통신 함수로 전달합니다.",
    ),
    "wheel_only_native": Rule("REVIEW", "sdist에는 없고 wheel에만 네이티브 바이너리가 있습니다."),
    "entry_point_mismatch": Rule("REVIEW", "sdist와 wheel이 서로 다른 실행 진입점을 등록합니다."),
    "python_ast_mismatch": Rule(
        "REVIEW", "같은 경로의 Python 코드가 의미 있는 AST 차이를 보입니다."
    ),
    # Defensive error reporting required by the public contract.
    "artifact_identity_mismatch": Rule(
        "REVIEW", "sdist와 wheel의 프로젝트명 또는 버전이 서로 다릅니다."
    ),
    "unsupported_wheel_scope": Rule(
        "REVIEW", "F9 지원 범위가 아닌 네이티브 또는 플랫폼 종속 wheel입니다."
    ),
    "ast_parse_failed": Rule("REVIEW", "Python 소스를 파싱할 수 없어 수동 검토가 필요합니다."),
    "analysis_limit_exceeded": Rule("REVIEW", "Python 소스가 분석 복잡도 한도를 초과했습니다."),
    "analyzer_error": Rule("REVIEW", "분석기가 입력을 처리하지 못해 수동 검토가 필요합니다."),
}


STANDARD_BUILD_BACKENDS = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "flit_core.buildapi",
        "poetry.core.masonry.api",
        "hatchling.build",
        "pdm.backend",
        "maturin",
        "scikit_build_core.build",
    }
)

KNOWN_BUILD_REQUIREMENTS = frozenset(
    {
        "setuptools",
        "wheel",
        "flit-core",
        "poetry-core",
        "hatchling",
        "pdm-backend",
        "maturin",
        "scikit-build-core",
    }
)


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
