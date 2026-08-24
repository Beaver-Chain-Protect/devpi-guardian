# devpi-guardian F6·F7 설계

- 문서 상태: 승인된 설계 (구현 완료 후 확정 기록)
- 작성일: 2026-08-19
- 담당: F6 신뢰 baseline 선택, F7 baseline 대비 차분 분석
- 범위: F6 baseline 릴리스 선택, F7 아티팩트 차분 판정
- 구현 저장소: `devpi-guardian`

> **사후 기록 안내:** 이 문서는 구현이 끝난 뒤 실제로 확정된 결정을
> 기록한 것이다. 아래의 모든 규칙은 `tests/baseline/` 아래 테스트로
> 고정되어 있으며, 문서와 코드가 어긋나면 테스트가 기준이다.

## 1. 목적

이 문서는 새로 올라온 Artifact를 **이미 승인된 같은 프로젝트의 이전
릴리스와 비교**해서, 그 릴리스에는 없던 위험 증거만 골라내는 방법을
정의한다.

성공 조건은 다음과 같다.

> 이전에 `ALLOW`로 승인된 baseline이 이미 갖고 있던 증거는 다시 보고하지
> 않고, baseline에 없던 증거만 보고한다.

F8이 아티팩트 하나를 통째로 스캔하는 것과 달리, F6·F7은 **버전 간 변화**를
본다. 기존 파일에 몰래 끼워 넣은 코드를 잡는 것이 존재 이유다.

## 2. 범위와 비범위

### 포함

- 승인된 릴리스 중 비교 대상 baseline 선택 (F6 우선순위 체인)
- baseline과 신규 아티팩트의 파일 목록·내용 비교 (F7 1단계)
- 신규·변경된 Python 파일에 대한 F8 판정 로직 실행 (F7 2·3단계)
- 신규 import·호출 목록을 참고 정보로 수집 (F7 4단계)
- 모든 Finding에 baseline 대비 출처(origin) 표시
- F4 판정 저장소 조회 어댑터
- baseline 아티팩트 바이트의 HTTP(S) 취득과 SHA-256 검증

### 제외

- 판정 규칙 자체의 신규 설계 — 전부 F8·F9 것을 호출한다
- `analyzers.install_surface`의 아티팩트 전체 단위 규칙
  (build backend, `cmdclass`, 빌드 의존성 등)
- 정책 점수 산출과 최종 verdict 결정 (F10)
- 워커 오케스트레이션과 lease 관리 (F5)
- 인증 방식 결정 — HTTP 세션 주입으로 분리한다

## 3. 선택한 접근

### 3.1 F6: 티어 우선 우선순위 체인

비교 가능성이 높은 순서로 티어를 정하고, **각 티어를 모든 이전 버전에
걸쳐 먼저 훑은 뒤** 다음 티어로 넘어간다.

| 순서 | 티어 | 조건 |
| --- | --- | --- |
| 1 | `same_tag` | wheel 호환성 tag 문자열이 대상과 정확히 일치 |
| 2 | `universal_wheel` | abi=`none`, platform=`any`인 순수 Python wheel |
| 3 | `sdist` | sdist |
| 4 | 없음 | `has_baseline=False` |

- 티어가 버전보다 우선한다. `same_tag`가 0.0.1이고 universal wheel이
  8.9.0이어도 `same_tag`가 이긴다.
- 각 티어 안에서는 **대상보다 낮은 버전 중 가장 높은 것**을 고른다.
- 같은 버전이 여럿이면 filename 최소값으로 고정한다. 조회 순서와
  무관하게 결과가 같아야 한다.
- 대상이 sdist면 tag가 없으므로 1·2단계를 건너뛰고 sdist 티어만 쓴다.
- 대상이 wheel인데 filename에서 tag를 읽을 수 없으면 1단계만 건너뛴다.

### 3.2 버전 비교

`packaging.version.Version`으로 비교한다.

- 프리릴리스는 대상보다 낮으면 정상 후보다 (`2.0.0rc1` < `2.0.0`).
- PEP 440으로 파싱할 수 없는 버전은 순서를 정의할 수 없으므로 후보에서
  제외하고 사유를 `logging.DEBUG`로 남긴다.
- 대상 버전 자체가 파싱 불가면 baseline을 선택하지 않는다.

### 3.3 tag 판정 불가 시 fail-closed

후보 wheel의 tag를 읽을 수 없으면 **"universal wheel이 아니다"로 명시적으로
판정**해 모든 wheel 티어에서 탈락시킨다. "판정 불가 → 조건 검사 생략 →
통과" 경로는 구조적으로 존재하지 않는다.

`acme-py3-none-any.whl`처럼 마지막 세 토큰이 universal tag 그 자체인
파일명도 전체 형태가 유효하지 않으므로 탈락한다.

### 3.4 F7: 차분이지 재스캔이 아니다

파일 비교는 **경로와 바이트**만 본다. 아카이브 멤버 타임스탬프는 읽지
않으므로 시각 차이가 변경으로 오인되지 않는다.

- `added`: baseline에 없던 경로
- `changed`: 경로는 같고 SHA-256이 다른 파일
- `removed`, `unchanged`: 참고 정보

`.dist-info`/`.egg-info` 내부, `RECORD`, `METADATA`, `WHEEL`, `INSTALLER`,
`PKG-INFO`, 서명 파일은 비교 대상에서 제외한다.

`added`와 `changed`만 분석한다. baseline이 이미 갖고 있던 채로 바뀌지 않은
파일은 한 번 승인된 것이므로 다시 판정하지 않는다.

### 3.5 차집합 + carried 원칙

`changed` 파일은 전체를 분석하되, **baseline 버전이 이미 갖고 있던 증거는
finding으로 올리지 않고 carried 목록에 기록**한다.

이 원칙이 없으면 다음 모순이 생긴다.

| 상황 | 차집합 없음 | 차집합 있음 |
| --- | --- | --- |
| 파일 무변경, 기존 증거 유지 | 보고 안 함 | 보고 안 함 |
| 주석 한 줄 추가, 기존 증거 유지 | **보고함** (모순) | 보고 안 함 |
| 기존 증거 + 신규 증거 추가 | 둘 다 보고 | 신규만 보고 |

동일성 판정에서 **줄번호는 제외**한다. 코드가 밀릴 때마다 기존 증거가
신규로 잡히기 때문이다.

- credential 흐름: `(source, sink, snippet)`
- 위험 호출·동적 import: `(qualified_name, snippet)`
- `.pth` 줄: 공백 제거한 줄 텍스트
- entry point: 정규화된 entry 문자열

`snippet`을 동일성에 포함하므로, 같은 토큰을 다른 URL로 보내도록 바꾼
변경은 신규로 잡힌다.

baseline 버전을 읽거나 파싱할 수 없으면 차집합을 적용하지 않고 전량
보고한다 (fail-closed).

### 3.6 entry point는 파일이 아니라 집합으로 비교

`entry_points.txt`는 `.dist-info` 안에 있어 파일 비교에서 제외되고,
디렉터리 이름에 버전이 들어가므로 (`demo-1.0.0.dist-info` →
`demo-2.0.0.dist-info`) 경로 기준으로는 릴리스마다 `added`+`removed`로
갈라져 비교 자체가 성립하지 않는다.

따라서 `.dist-info` 제외 규칙은 **그대로 두고**, entry point만 별도 축으로
비교한다. F9의 `_collect_entry_points`가 `entry_points.txt`, `setup.cfg`,
`pyproject.toml`, `setup.py` 네 곳을 정규화된 문자열 집합으로 파싱하므로,
그 집합의 차집합을 쓴다. sdist baseline과 wheel 대상도 이 방식으로 비교
가능해진다.

### 3.7 F8 재사용 방침

F7은 **판정 로직을 새로 만들지 않는다.** 전부 F8·F9 함수를 호출한다.

| 재사용 대상 | 용도 |
| --- | --- |
| `astutil.find_credential_network_flows` | credential→network 흐름 |
| `astutil.scan_calls` | 위험 호출·동적 import 분류 |
| `astutil.parse_python`, `build_alias_table` | AST 파싱, import 목록 |
| `archive.extract_artifact` | 비실행 안전 압축 해제 |
| `sdist_wheel._executable_pth_lines` | 실행형 `.pth` 줄 |
| `sdist_wheel._collect_entry_points` | entry point 파싱 |
| `sdist_wheel._strip_sdist_prefix`, `_wheel_paths`, `_ignored` | 경로 정규화·제외 |
| `sdist_wheel._read_python` | 인코딩 선언 처리 |
| `serialization.finding_fingerprint` | 증거 동일성 (직접 계산 금지) |
| `types.Finding`, `make_finding`, `sort_findings` | Finding 생성·정렬 |

경로 정규화와 인코딩 처리를 F7이 다시 구현하면 F9와 갈라질 수 있으므로,
이름 앞에 `_`가 붙은 내부 함수라도 재사용한다. 병합 후 같은 패키지다.

### 3.8 Finding은 확장하지 않는다

`Finding`은 frozen dataclass이며 F7이 필드를 늘리지 않는다. baseline 대비
출처는 반환 타입을 `list[tuple[Finding, Origin]]`으로 감싸 전달한다.

`Origin`은 `diff_new`(baseline에 없던 것), `diff_changed`(내용이 바뀐 파일에서
나온 것), `diff_artifact`(특정 파일에 귀속되지 않는 아카이브 수준) 셋이다.

## 4. 전체 구조

```
src/devpi_guardian/baseline/
    __init__.py          공개 API 재노출
    selection.py         F6 우선순위 체인
    diff.py              F7 차분 판정 + F6·F7 orchestration
    release_lookup.py    F4 조회 어댑터
    artifact_source.py   HTTP(S) baseline 취득
```

```
F5 워커
  └─ compare_release_to_baseline(target, artifact_path, lookup, bytes_source)
       ├─ select_baseline                  (F6)
       │    └─ ReleaseLookup.allowed_releases  → VerdictReaderReleaseLookup → F4
       ├─ ArtifactBytesSource.open              → HttpArtifactBytesSource → devpi
       └─ diff_against_baseline            (F7)
            ├─ extract_artifact  ×2        (F8)
            ├─ 파일 목록·바이트 비교
            ├─ 신규/변경 파일 판정         (F8 함수 호출)
            └─ entry point 집합 차집합     (F9 함수 호출)
```

## 5. 규칙과 action

F7 전용 규칙은 `DIFF_RULES`에 둔다. action은 대응하는 F8·F9 규칙과 1:1로
일치시킨다.

| F7 규칙 | action | 대응 |
| --- | --- | --- |
| `baseline_new_credential_network` | DENY | `wheel_only_credential_network` |
| `baseline_new_risky_python` | DENY | `wheel_only_risky_python` |
| `baseline_new_executable_pth` | DENY | `wheel_only_executable_pth` |
| `baseline_new_native` | REVIEW | `wheel_only_native` |
| `baseline_new_entry_point` | REVIEW | `entry_point` |

오류 보고는 F8의 공용 규칙을 그대로 쓴다: `ast_parse_failed`,
`analysis_limit_exceeded`, `analyzer_error`. `extract_artifact`가 만드는
`archive_unsafe_member`, `archive_bomb`은 `diff_artifact` 출처로 전달한다.

네이티브 바이너리는 **`added`일 때만** 보고한다. 릴리스마다 재빌드되어
바이트가 항상 바뀌므로 `changed`까지 올리면 모든 네이티브 릴리스가 영구
REVIEW가 되어 신호가 사라진다.

## 6. 주입 지점과 인증 분리

F6은 두 개의 Protocol로 외부 의존성을 분리한다.

```python
class ReleaseLookup(Protocol):
    def allowed_releases(self, project: str) -> list[ReleaseRecord]: ...


class ArtifactBytesSource(Protocol):
    def open(self, sha256: str) -> Path: ...
```

### 6.1 ReleaseLookup 구현체

`VerdictReaderReleaseLookup`은 F4의 reader를 **생성자 주입**으로 받는다.
reader를 어디서 얻을지는 wiring의 몫이다 (README 기준
`pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]`).

요구 인터페이스는 `list_allowed_releases` 하나뿐인 좁은 Protocol로 잡는다.
baseline 선택은 enforcement decision을 요구할 이유가 없다. 모든
`VerdictReader`가 이를 만족한다.

`StoreUnavailable`은 **삼키지 않고 전파**한다. 빈 목록을 돌려주면
"저장소 장애"와 "프로젝트 첫 릴리스"가 구별되지 않는다.

`AllowedRelease.origin_url`을 `ReleaseRecord`가 담지 않으므로, 어댑터가
sha256→origin_url을 기억해 `origin_url(sha256)` resolver 역할을 겸한다.

### 6.2 ArtifactBytesSource 구현체

`HttpArtifactBytesSource`는 HTTP 세션을 **생성자 주입**으로 받고, 세션에
어떤 인증이 설정돼 있는지 알지 못한다. 세션에 전달하는 인자는
`url`, `stream`, `timeout` 뿐이다. F5가 인증 방식을 확정하면 세션을 만드는
wiring만 바뀌고 이 클래스는 손대지 않는다.

- 다운로드 후 SHA-256을 재계산해 불일치 시 예외를 던지고 부분 파일을
  삭제한다. F4는 URL을 fetch하거나 재해싱하지 않으므로 이 검증이 유일한
  방어선이다.
- `http`/`https` 스킴만 허용한다. F4의 sanitizer는 스킴을 제한하지 않으며,
  README가 `origin_url`을 신뢰 우회나 로컬 open으로 쓰지 말 것을 요구한다.
- 임시 파일 이름은 `<digest>-<origin_url의 파일명>`으로 둔다.
  `extract_artifact`가 확장자로 아카이브 형식을 판별하므로 digest만으로는
  추출이 실패한다.
- context manager로 받아둔 임시 파일을 정리한다.
- 4xx/5xx, 연결 실패, 타임아웃, TLS 실패를 모두 `ArtifactDownloadError`
  하나로 정규화한다. 호출자가 어떤 HTTP 라이브러리인지 알 필요가 없다.

## 7. orchestration 결과 계약

`compare_release_to_baseline`은 세 가지 결과를 구분한다.

| 상황 | `has_baseline` | `diff` | `findings` |
| --- | --- | --- | --- |
| 프로젝트 첫 릴리스 | `False` | `None` | `()` |
| baseline 선정, 차분 완료 | `True` | 차분 결과 | 차분 findings |
| baseline 바이트 취득 실패 | `True` | `None` | `analyzer_error` |
| F4 조회 실패 | `False` | `None` | `analyzer_error` |

첫 릴리스는 오류가 아니다. 깨진 filestore나 조회 실패가 첫 릴리스로
오인되지 않도록 `has_baseline`과 `analyzer_error`를 함께 쓴다.

`baseline_sha256`은 F5가 `VerdictInput.baseline_sha256`에 그대로 넣는 값이다.
baseline 없음이 조용한 생략이 아니라 `None`으로 저장소까지 전달된다.

## 8. 다른 작업자 연결 방법

### 8.1 F4 — 판정 저장소

`SQLiteVerdictReader.list_allowed_releases(project)`만 사용한다. 어댑터가
`AllowedRelease`를 `ReleaseRecord`로 변환하고, 여러 stage에 같은 sha256이
있으면 하나로 접는다.

### 8.2 F5 — 워커

세션과 reader를 만들어 두 어댑터를 조립하고
`compare_release_to_baseline`을 호출한다. 임시 파일 정리는
`HttpArtifactBytesSource`를 `with`로 감싸면 끝난다.

### 8.3 F8·F9 — 분석기

F7이 단방향으로 호출한다. F8·F9는 F6·F7을 알지 못한다.

F7 findings는 **F8 전체 스캔 결과와 함께 소비해야 한다.** F7은 변화만
보므로, 아티팩트 자체의 설치 표면 위험은 F8이 담당한다.

### 8.4 F10 — 정책 엔진

`findings`의 각 항목을 `EvidenceInput`으로 변환할 때, `Origin`과
`selection.tier`를 `EvidenceInput.details`에 함께 넣어야 한다.

`selection.tier`는 baseline이 **얼마나 비교 가능했는지**를 말한다. tag
정확 일치는 sdist 폴백보다 훨씬 강한 근거이며, 같은 finding이라도 무게가
달라야 한다. `VerdictInput`에 tier 필드가 없고 `Finding`도 확장하지 않으므로,
findings만 순회하는 변환 루프는 tier를 조용히 떨어뜨린다.
`EvidenceInput.details`가 스키마 변경 없이 이를 받는 유일한 자리다.

## 9. 완료 기준

### 9.1 F6 완료 기준

- 우선순위 체인 네 단계가 티어 우선으로 동작한다
- 티어 안에서 가장 높은 낮은-버전을 고르고, 동률은 filename으로 확정한다
- 조회 순서를 뒤집어도 같은 baseline을 고른다
- 프리릴리스는 후보, 파싱 불가 버전은 제외되며 사유가 로그에 남는다
- tag 판정 불가 후보가 모든 wheel 티어에서 명시적으로 탈락한다
- 대상 자신은 절대 자신의 baseline이 되지 않는다

### 9.2 F7 완료 기준

- 타임스탬프 차이가 `changed`를 만들지 않는다
- `.dist-info` 내부와 메타데이터 파일이 비교에서 빠진다
- sdist 접두사와 `src/` 레이아웃이 wheel 경로로 정규화된다
- baseline이 이미 갖던 증거는 finding이 아니라 carried로 간다
- 주석 한 줄만 바뀐 파일과 전혀 안 바뀐 파일의 판정이 같다
- 기존 파일에 끼워 넣은 증거가 `diff_changed`로 잡힌다
- `Finding`에 필드가 늘어나지 않았다
- 어떤 예외도 호출자에게 새어 나가지 않는다

### 9.3 어댑터 완료 기준

- 실제 SQLite DB를 만들어 `list_allowed_releases`를 통과시킨다
- `StoreUnavailable`이 `analyzer_error`로 이어진다
- 인증 설정이 다른 세션들이 동일하게 동작한다
- 세션에 전달되는 인자가 `url`·`stream`·`timeout` 뿐이다
- SHA-256 불일치가 예외를 만들고 파일을 남기지 않는다
- 다운로드한 파일이 `extract_artifact`로 추출 가능하다

### 9.4 필수 테스트 묶음

- `tests/baseline/test_selection.py` — F6 체인
- `tests/baseline/test_diff.py` — F7 차분과 판정
- `tests/baseline/test_release_lookup.py` — 실제 DB 기반 F4 연동
- `tests/baseline/test_artifact_source.py` — 가짜 세션과 로컬 HTTP 서버
- `tests/baseline/test_wiring.py` — 실제 어댑터 end-to-end

## 10. 확정된 구현 기준

- 패키지 구조: `src/devpi_guardian/baseline`
- 추가 런타임 의존성: `packaging` (버전 비교), HTTP 세션은 주입
- `selection.py`는 devpi-server 코드를 import하지 않는다. F8 analyzers와
  같은 성질을 유지하기 위해 SHA-256 검증 정규식만 국소 복제하고 출처를
  주석으로 남긴다.
- `release_lookup.py`만 `verdicts`를 import한다.

실행 가능한 작업 순서와 각 단계의 테스트 기준은
`docs/superpowers/plans/2026-08-19-f6-f7-baseline-diff.md`에 둔다.
