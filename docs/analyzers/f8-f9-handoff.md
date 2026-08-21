# F8/F9 분석기 연동 안내

이 문서는 `devpi-guardian` 가운데 **F8 설치 공격 표면 검사**와
**F9 sdist-wheel 불일치 분석**의 사용 방법과 팀 연동 계약을 설명합니다.
wheel 또는 sdist의 코드를 import하거나 실행하지 않고, 아카이브를 정적으로 확인한 뒤
결정적인 `Finding` 목록을 반환합니다.

F8은 wheel의 `dist-info/RECORD` 파일 목록·해시·크기 무결성, `setup.py`, 비표준 빌드 설정,
`.data/scripts/<file>` 설치 스크립트, `.pth`, customize 모듈, 제한된 import 시점 부작용,
entry point, 네이티브·실행 파일, 경로 이탈과 압축 폭탄을 검사합니다. F9는 정상적인
빌드 메타데이터 차이를 제거하고 Python AST를 정규화한 뒤, wheel에만 추가된 위험
코드·실행 가능한 `.pth`·네이티브 파일과 entry point/AST 불일치를 보고합니다.
`src/` 기반 sdist와 wheel 루트의 차이, 서로 다른 entry point 표기도 비교 전에
정규화합니다.

이 모듈은 devpi 훅, 판정 DB, 워커, REST API, CLI 또는 최종 `ALLOW/REVIEW/DENY`
정책을 구현하지 않습니다. 결과가 비어 있다는 것은 정의된 규칙에서 탐지되지 않았다는
뜻일 뿐, artifact가 안전하다는 보증이 아닙니다.

## 디렉터리 구조

```text
src/devpi_guardian/analyzers/    F8/F9 실제 분석 코드와 JSON 스키마
tests/analyzers/                 분석기 단위·계약·통합 스모크 테스트
tools/                           corpus 평가와 시연 도구
docs/analyzers/                  분석기 인수인계 문서
```

팀 저장소에 합칠 때도 `src/devpi_guardian/analyzers/` 경로와 아래 공개 import를
유지하면 호출하는 쪽의 코드를 변경하지 않아도 됩니다.

## 요구 환경

- Python 3.11 이상
- 런타임 의존성 없음(표준 라이브러리만 사용)
- 개발/테스트 의존성: `pytest`

## 공개 함수와 사용 예시

```python
from devpi_guardian.analyzers import (
    AnalysisLimits,
    compare_sdist_wheel,
    compare_sdist_wheel_isolated,
    dumps_report,
    scan_install_surface,
    scan_install_surface_isolated,
)

f8_findings = scan_install_surface("dist/demo-1.0.1-py3-none-any.whl")
f9_findings = compare_sdist_wheel(
    "dist/demo-1.0.1.tar.gz",
    "dist/demo-1.0.1-py3-none-any.whl",
)

for finding in [*f8_findings, *f9_findings]:
    location = f"{finding.file}:{finding.line}" if finding.line else finding.file
    print(f"[{finding.action}] {finding.rule} {location} - {finding.message}")
    if finding.source and finding.sink:
        print(f"  flow: {finding.source} -> {finding.sink}")
    if finding.snippet:
        print(f"  evidence: {finding.snippet}")

# 정책 엔진이나 REST API로 전달할 결정적인 JSON 보고서
report_json = dumps_report(
    f8_findings,
    analyzer="F8",
    artifact_sha256="0" * 64,
)

# 신뢰하지 않는 큰 입력은 별도 프로세스에서 제한 시간을 두고 검사할 수 있습니다.
limits = AnalysisLimits(timeout_seconds=20, memory_limit_mb=512)
f8_isolated = scan_install_surface_isolated("dist/demo.whl", limits=limits)
f9_isolated = compare_sdist_wheel_isolated("dist/demo.tar.gz", "dist/demo.whl", limits=limits)
```

일반 함수는 잘못된 입력이나 손상된 artifact에 대해 예외를 노출하지 않고
`analyzer_error` 또는 `ast_parse_failed` 근거를 반환합니다. sdist가 없거나 경로가
유효하지 않은 경우 F9 비교는 명세대로 생략되어 빈 목록을 반환합니다.

JSON 보고서에는 `schema_version`, `ruleset_version`, 분석기 종류와 정렬된 Finding이
포함되며 타임스탬프는 넣지 않아 같은 입력에서 같은 결과를 만듭니다. 각 Finding의
안정적인 SHA-256 `fingerprint`는 직렬화 단계에서 생성됩니다. 함께 배포되는
`finding-report-v1.schema.json`으로 다른 컴포넌트의 입력 형식을 검증할 수 있습니다.

격리 함수는 모든 운영체제에서 하위 프로세스와 제한 시간을 사용합니다. 메모리 제한은
POSIX 환경에서 적용되며 Windows에서는 제한 시간이 안전장치로 동작합니다. 제한 초과나
작업 프로세스 오류는 호출자에게 예외를 던지는 대신 `analyzer_error`로 반환합니다.

## 팀 연동 계약

F8에는 분석할 wheel 또는 sdist의 로컬 파일 경로를 전달합니다. F9에는 같은 프로젝트와
버전의 sdist 및 wheel 경로를 함께 전달합니다. 따라서 다운로드 담당 컴포넌트가
artifact SHA-256뿐 아니라 실제 저장 경로와 같은 버전의 파일 쌍을 제공해야 합니다.

wheel에는 정확히 하나의 `*.dist-info/RECORD`가 있어야 합니다. F8은 RECORD를 UTF-8
CSV로 읽어 모든 추출 regular file의 목록·SHA-256 이상 해시·크기를 검증하며, 목록이
없거나 모호하거나 불일치하면 `wheel_record_missing` 또는 `wheel_record_integrity`
DENY Finding을 반환합니다. `RECORD.jws`와 `RECORD.p7s` 서명 형제는 호환성을 위해
목록에서 생략할 수 있습니다. 이 검사는 `.whl`에만 적용되고 sdist `.zip`/`.tar*`에는
적용되지 않습니다.

F8 wheel 설치 스크립트 규칙은 다음과 같습니다.

| 규칙 | 기본 action | 적용 범위 |
| --- | --- | --- |
| `wheel_install_script` | REVIEW | wheel 최상위 `<distribution>.data/scripts/<file>` regular file 하나당 한 건 |
| `wheel_install_script_risky` | REVIEW | Python으로 인식된 설치 스크립트의 process/network/dynamic-exec/file-write 호출 및 지정된 literal dynamic import |
| `wheel_install_script_credential_network` | DENY | credential source가 network sink로 흐르는 확인된 데이터 흐름 |

스크립트 Python 인식은 `.py`/`.pyw`, `#!python`/`#!pythonw`, 일반적인 python·python3·python.exe
shebang으로 제한합니다. 파싱 실패 시에도 일반 설치 스크립트 REVIEW는 유지하며,
sdist의 유사한 경로·중첩 또는 lookalike `.data` 경로는 wheel 설치 스크립트 규칙에서 제외합니다.
설치 스크립트의 `setup.py` basename은 build-time `setup.py`로 중복 분류하지 않습니다.

반환값은 정렬된 `Finding` 목록이며 주요 필드는 다음과 같습니다.

- `rule`: 탐지 규칙 ID
- `action`: 분석기가 권고하는 `REVIEW` 또는 `DENY` 수준
- `file`, `line`: 근거 위치
- `message`, `snippet`: 사람이 확인할 설명과 증거
- `source`, `sink`: 확인된 데이터 흐름

분석기의 `action`은 근거별 권고 수준입니다. 최종 판정은 정책·집계 컴포넌트가 다른
분석 결과와 함께 결정해야 합니다. F4 증거 저장 모델과 연결할 때는 `rule`, `action`,
`file`, `line`, `message`를 대응시키고 `snippet`, `source`, `sink`, `fingerprint`는
세부 정보 객체에 보관하면 됩니다.

## 오프라인 패키지 묶음 평가

실제 정상·악성 fixture를 여러 개 모아 오탐과 탐지 결과를 집계하려면 다음 형식의
manifest를 작성합니다. 모든 경로는 manifest 파일 기준 상대경로로 사용할 수 있습니다.

```json
{
  "f8": [
    {"name": "normal-wheel", "artifact": "artifacts/demo-1.0.0.whl"}
  ],
  "f9": [
    {
      "name": "release-pair",
      "sdist": "artifacts/demo-1.0.0.tar.gz",
      "wheel": "artifacts/demo-1.0.0-py3-none-any.whl"
    }
  ]
}
```

```text
.venv\Scripts\python -m tools.corpus_report corpus.json -o corpus-report.json
```

보고서는 case별 SHA-256·Finding과 전체 action/rule 빈도를 제공합니다. 실제 패키지
코드는 실행하지 않으며, 서로 다른 프로젝트명이나 버전의 sdist와 wheel은 비교 전에
`artifact_identity_mismatch`로 중단합니다.

PyPI의 최신 정상 패키지 쌍으로 묶음을 준비할 수도 있습니다. 다운로드 단계만 네트워크를
사용하고, PyPI가 제공한 크기와 SHA-256을 확인한 뒤 분석 자체는 로컬에서 수행합니다.

```text
.venv\Scripts\python -m tools.fetch_pypi_corpus attrs idna packaging six --strict
.venv\Scripts\python -m tools.corpus_report .corpus\corpus.json -o .corpus\corpus-report.json
```

## 대회 시연

실제 악성 코드를 보관하거나 실행하지 않고도 F8/F9 탐지를 보여 주는 합성 시나리오를
만들 수 있습니다. sdist에는 없지만 wheel에만 자격 증명 전송 코드와 시작 훅이 추가된
상황을 생성하고, artifact와 JSON 보고서를 `.demo`에 저장합니다.

```text
.venv\Scripts\python -m tools.demo_scenario --output-dir .demo
```

팀 인수인계 시에는 다음 한 줄로 공개 함수, 예상 탐지 규칙, JSON 왕복 변환과
fingerprint 규격을 함께 확인할 수 있습니다. 성공하면 `"status": "ok"`를 출력하고
종료 코드 0을 반환합니다.

```text
.venv\Scripts\python -m tools.integration_smoke --output-dir .demo
```

## 테스트

```text
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
```

테스트 fixture는 모두 임시 디렉터리에 프로그램으로 생성되며, 실제 악성 패키지나
고정 바이너리 fixture를 저장소에 포함하지 않습니다. GitHub Actions에서는 Linux의
Python 3.11~3.13과 Windows의 Python 3.11을 검사하며, 외부 Action은 공급망 변조를
줄이기 위해 릴리스 태그가 아닌 전체 commit SHA로 고정했습니다.

## 라이선스

MIT License. 자세한 내용은 저장소 루트의 `LICENSE`를 확인하세요.
