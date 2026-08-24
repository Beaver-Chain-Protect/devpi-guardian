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
정규화합니다. 또한 sdist의 `PKG-INFO`와 wheel의 `*.dist-info/METADATA`에서
`Requires-Dist`를 비교해 런타임 의존성 변경을 `REVIEW`로 보고합니다.

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

# F5 and any worker handling untrusted artifacts MUST use the isolated APIs.
limits = AnalysisLimits(timeout_seconds=20, memory_limit_mb=512)
f8_findings = scan_install_surface_isolated(
    "dist/demo-1.0.1-py3-none-any.whl", limits=limits
)
f9_findings = compare_sdist_wheel_isolated(
    "dist/demo-1.0.1.tar.gz",
    "dist/demo-1.0.1-py3-none-any.whl",
    limits=limits,
)

# Direct APIs are for trusted offline tooling and unit tests only.
trusted_f8 = scan_install_surface("dist/demo-1.0.1-py3-none-any.whl")
trusted_f9 = compare_sdist_wheel(
    "dist/demo-1.0.1.tar.gz", "dist/demo-1.0.1-py3-none-any.whl"
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

# F5/워커가 신뢰하지 않는 입력을 처리할 때는 반드시 위의 isolated API만
# 호출해야 합니다. direct API는 신뢰된 오프라인 도구와 단위 테스트 전용입니다.
```

일반 함수는 잘못된 입력이나 손상된 artifact에 대해 예외를 노출하지 않고
`analyzer_error` 또는 `ast_parse_failed` 근거를 반환합니다. sdist가 없거나 경로가
유효하지 않은 경우 F9 비교는 명세대로 생략되어 빈 목록을 반환합니다.

JSON 보고서에는 `schema_version`, `ruleset_version`, 분석기 종류와 정렬된 Finding이
포함되며 타임스탬프는 넣지 않아 같은 입력에서 같은 결과를 만듭니다. 각 Finding의
안정적인 SHA-256 `fingerprint`는 직렬화 단계에서 생성됩니다. 함께 배포되는
`finding-report-v1.schema.json`으로 다른 컴포넌트의 입력 형식을 검증할 수 있습니다.

격리 함수는 모든 운영체제에서 하위 프로세스와 제한 시간을 사용합니다. `memory_limit_mb`는
POSIX의 best-effort `RLIMIT_AS`일 뿐이며 Windows 또는 지원되지 않는 POSIX에서는 하드
보장이 아닙니다. 하드 메모리 집행이 필요한 배포 환경은 OS 또는 컨테이너 수준의 별도
메모리 제한을 제공해야 합니다. 제한 초과나 작업 프로세스 오류는 호출자에게 예외를
던지는 대신 `analyzer_error`로 반환합니다.

### 신뢰 경계 계약

F5 및 아티팩트를 신뢰하지 않는 운영 워커 코드는 반드시
`scan_install_surface_isolated`와 `compare_sdist_wheel_isolated`만 호출해야 합니다.
`scan_install_surface`와 `compare_sdist_wheel` 직접 API는 신뢰된 오프라인 도구와 단위
테스트에서만 사용합니다. 격리 API의 프로세스·시간 제한만으로 하드 메모리 격리를
주장하지 않으며, 필요한 경우 배포 환경의 OS/컨테이너 정책을 함께 적용해야 합니다.

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

F8의 `setup.py`, `pyproject.toml`, `setup.cfg` 빌드 설정은 sdist에서만 활성화합니다.
아카이브 루트의 파일 또는 모든 파일이 공유하는 통상적인 sdist 공통 루트 바로 아래의
파일만 프로젝트 빌드 설정으로 취급하며, `docs/example/` 같은 중첩 파일과 wheel의
루트 lookalike는 무시합니다. wheel의 `*.dist-info/entry_points.txt`는 설치 메타데이터로
계속 검사합니다.

PEP 517 `build-system.backend-path`는 다음 규칙으로 제한적으로 기록합니다.

| 규칙 | 기본 action | 적용 범위 |
| --- | --- | --- |
| `in_tree_build_backend` | REVIEW | 활성 sdist `pyproject.toml`의 비어 있지 않은 유효한 상대 경로 목록 또는 잘못된 설정의 방어적 근거 |
| `unsafe_backend_path` | DENY | 절대·드라이브 경로, NUL, 또는 `..`로 프로젝트 루트 밖으로 정규화되는 backend-path 항목 |

경로는 파일시스템을 resolve하거나 backend 코드를 import·실행하지 않고 portable 구분자로
검사합니다. 유효 항목은 정렬·제한된 한 건으로 요약하고, 잘못된 항목은 별도 제한된 DENY
근거로 요약합니다. `backend/../backend_impl`처럼 정규화 후 소스 트리 안에 남는 경로는
유효한 in-tree backend로 처리합니다. 목록이 비어 있으면 근거를 만들지 않으며, 목록 타입이
아니거나 문자열이 아닌 항목이 있으면 `in_tree_build_backend` REVIEW 한 건으로 방어합니다.

F9 메타데이터 의존성 규칙은 다음과 같습니다.

| 규칙 | 기본 action | 적용 범위 |
| --- | --- | --- |
| `requires_dist_mismatch` | REVIEW | sdist `PKG-INFO`와 wheel `*.dist-info/METADATA`의 의미적으로 다른 `Requires-Dist` 집합 |

`Requires-Dist` 비교는 sdist의 `Metadata-Version`을 기준으로 합니다. 버전이 없거나
해석되지 않거나 2.2 미만이면 비교하지 않습니다. 2.2 이상 2.6 미만에서 sdist가
`Dynamic: Requires-Dist`를 선언하면 비교하지 않고, 그 외에는 두 집합이 같아야 합니다.
2.6 이상에서 `Dynamic: Requires-Dist`이면 wheel이 의존성을 추가하는 것은 허용하지만,
sdist의 값을 삭제하거나 변경하면 검토 대상입니다. `Dynamic` 이름과 쉼표로 나뉜
헤더 값은 대소문자를 구분하지 않습니다. 메타데이터 파일을 찾거나 읽지 못한 경우에는
이 규칙만 생략하고 다른 방어적 Finding은 유지합니다.

비교 시 프로젝트명과 extra 이름의 PEP 503 구분자·대소문자, extra 순서, 괄호·specifier
공백·절 순서를 정규화하고, marker는 값을 평가하지 않은 채 공백·인용부호만 보수적으로
정규화합니다. 직접 URL의 내부 의미는 보존합니다. 해석할 수 없는 요구사항은 안정적인
공백 정규화 표현으로 비교하며 예외를 외부에 노출하지 않습니다. 요구사항은 순서와
중복을 무시하는 집합으로 처리합니다. 근거는 `wheel 전용=[...]; sdist 전용=[...]`
형식으로 각 측 최대 5개와 `+N개`를 표시합니다.

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
