# devpi-guardian F1/F2 규범 명세

- 문서 상태: 구현 완료본
- 작성일: 2026-08-20
- 범위: F1 Guardian 인덱스, F2 Simple 링크 필터
- 기준: devpi-server 6.20.3, Python 3.11 이상

## 1. 목표

기존 devpi stage를 상속하는 읽기 전용 `guardian` 인덱스를 제공하고,
pip·uv가 조회하는 Simple 응답에는 SHA-256 기준 현재 유효 판정이 `ALLOW`인
Artifact 링크만 남긴다.

F2는 목록 노출 통제다. 직접 파일 URL 통제는 F3이며, 두 경로는 F4의 같은
`VerdictReader`와 판정 우선순위를 사용한다.

## 2. F1 Guardian 인덱스 계약

- devpi plugin hook `devpiserver_get_stage_customizer_classes`가
  `("guardian", GuardianStage)`를 등록한다.
- `GuardianStage`는 devpi가 동적으로 결합하는 `BaseStageCustomizer` 계약을
  따른다. 코어 구현 클래스를 직접 상속하지 않는다.
- `readonly = True`다.
- 생성·수정 설정에 비어 있지 않은 `bases`가 없으면
  `InvalidIndexconfig`로 거부한다.
- 일반 업로드 저장소나 별도 패키지 복사본을 만들지 않고, devpi의 기존 base
  상속과 mirror cache를 사용한다.

예시:

```console
devpi index -c root/guardian type=guardian bases=root/pypi
```

## 3. 공유 reader 초기화 계약

- `devpiserver_pyramid_configure`가 DB migration을 먼저 완료한다.
- migration 성공 후 `SQLiteVerdictReader`를 한 번 생성한다.
- 같은 객체를 기존 Pyramid registry key와 XOM의 충돌 방지 전용 속성에
  저장한다.
- F2는 `get_verdict_reader(stage.xom)`로 그 객체만 조회한다.
- 접근자는 reader 생성, migration, DB 경로 추론을 하지 않는다.
- 초기화 전에 호출되면 `StoreUnavailable`을 발생시킨다.
- migration이 실패하면 registry와 XOM에 부분 초기화 상태를 남기지 않는다.

## 4. F2 필터 알고리즘

입력 링크 순서대로 다음을 수행한다.

1. 링크 iterable을 정확히 한 번 순회한다.
2. `link.hashes["sha256"]`만 읽는다.
3. 소문자 64자리 16진수 SHA-256만 판정 조회 대상으로 인정한다.
4. 유효 digest가 하나 이상이면
   `get_effective_decisions(digests)`를 한 번만 호출한다.
5. digest별 결과의 `allowed is True`인 위치만 `True`로 반환한다.
6. 링크 수와 동일한 수의 boolean을 원래 순서대로 반환한다.

다음 링크는 숨긴다.

- SHA-256 누락, 다른 hash만 존재, 잘못된 길이·문자, 대문자 digest
- F4 mapping이 없는 Artifact
- `DISCOVERED`, `SCANNING`, `REVIEW`, `DENY`, `ERROR`
- mapping 응답 누락 또는 literal boolean이 아닌 truthy `allowed`

필터는 링크 객체, 파일명, URL, `requires-python`, yanked, core metadata를
변경하지 않는다. 허용된 링크의 상대 순서도 유지한다.

## 5. 장애와 보안 경계

- 유효 SHA-256이 있어 판정 조회가 필요한데 reader가 미초기화됐거나
  `StoreUnavailable`이면 Simple 요청 전체를 HTTP 503으로 중단하고
  `Retry-After: 5`를 보낸다.
- 유효 SHA-256 링크가 하나도 없으면 reader를 호출하지 않고 모두 숨긴다.
- 예상하지 않은 프로그래밍 예외는 빈 결과로 위장하지 않고 전파한다.
- SQL, override 만료, 상태 우선순위, F3의 내부 재검증 술어를 F2에 복제하지
  않는다. 공개 계약은 `EnforcementDecision.allowed` 하나다.

## 6. 비범위와 후속 의존성

- F1/F2는 PyPI를 주기적으로 크롤링하거나 Artifact를 선다운로드하지 않는다.
- F1/F2는 정적 분석, Security Diff, 설치 공격 표면 분석을 실행하지 않는다.
- F1/F2는 시간 기반 또는 위험도 기반 cooldown을 구현하지 않는다.
- 미판정 Artifact 발견·저장과 분석 큐 투입은 F5가 제공해야 한다.
- 직접 `+f`/`+e` URL은 F3가 모든 devpi index에 대해 통제한다.

따라서 F5가 후보를 발견하고 F4에 release mapping과 판정을 넣기 전에는 신규
Artifact가 Guardian Simple 응답에 영구적으로 보이지 않는다. 이것은 F2가
임의로 다운로드를 허용해 해결할 문제가 아니라, 통합 전에 반드시 닫아야 할
F5 계약이다.

## 7. 완료 기준과 증거

- Guardian index는 explicit base 없이는 생성되지 않고 읽기 전용이다.
- HTML 및 PEP 691 JSON Simple 응답이 같은 필터 결과를 보존한다.
- ALLOW, DENY, 미판정 세 Artifact 중 ALLOW만 목록과 설치 경로에서 성공한다.
- pip와 uv exact-version 설치에서 ALLOW는 성공하고 미판정은 실패한다.
- private base와 PyPI mirror cache miss·hit·stale 경로에서 필터가 유지된다.
- 필터를 우회한 DENY·미판정 직접 URL은 F3에서 차단된다.
- StoreUnavailable은 빈 200이 아니라 재시도 가능한 503이다.
- 기존 F3/F4 및 전체 테스트가 회귀 없이 통과한다.

근거 테스트:

- `tests/test_package.py`
- `tests/test_guardian_stage.py`
- `tests/integration/test_pytest_devpi_server.py`
- `tests/integration/test_f1_f2_broader.py`

devpi는 Guardian의 SRO에 포함된 각 base 결과마다 F2 필터를 호출한다. 따라서
한 프로젝트 응답의 판정 DB batch 횟수는 링크를 제공한 base 수 이하이며,
base 전체를 합치려고 devpi 코어의 SRO 병합 로직을 복제하지 않는다.
