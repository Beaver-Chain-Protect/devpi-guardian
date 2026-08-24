# Verdict Baseline Tier 설계

- 작성일: 2026-08-21
- 상태: 승인됨
- 범위: F6 baseline 선택 근거를 F10과 F4 판정 이력까지 전달·보존

## 1. 배경

F6는 승인된 비교 대상을 선택하면서 선택 품질을 `selection.tier`에 기록한다.
가능한 값은 `same_tag`, `universal_wheel`, `sdist`다. 현재 `VerdictInput`에는
이 값을 담는 필드가 없어 F10 경계에서 선택 근거가 사라지고, F10은 신뢰도가 낮은
`sdist` 비교와 더 강한 비교를 구분할 수 없다.

## 2. 목표와 비목표

이 변경은 다음을 보장한다.

- F6의 `selection.tier`를 F10이 동일한 값으로 받는다.
- F10이 만든 `VerdictInput`과 F4의 불변 verdict 이력에 tier가 남는다.
- 새 판정은 baseline SHA-256과 tier를 항상 함께 제공한다.
- 런타임과 SQLite가 허용된 세 값 외의 tier를 거부한다.
- 기존 SQLite DB와 과거 판정 이력을 손실 없이 마이그레이션한다.

F10의 tier별 점수나 정책 규칙 자체는 이 변경의 범위가 아니다. F4의 public reader에
tier 조회 API를 새로 추가하지도 않는다.

## 3. 도메인 계약

`devpi_guardian.verdicts.models`에 다음 공개 타입 별칭을 둔다.

```python
BaselineTier = Literal["same_tag", "universal_wheel", "sdist"]
```

`VerdictInput`에는 기본값 없는 필드가 추가된다.

```python
baseline_sha256: str | None
baseline_tier: BaselineTier | None
```

기본값을 제공하지 않는 이유는 기존 호출자가 tier 전달을 실수로 생략하는 것을 막기
위해서다. baseline을 찾지 못한 판정은 두 필드를 모두 `None`으로 전달한다. baseline이
있다면 두 필드는 모두 존재해야 하며, `baseline_tier`는 정확히 `same_tag`,
`universal_wheel`, `sdist` 중 하나여야 한다. `str`의 하위 클래스나 다른 타입은 받지
않는다.

F6와 F10의 데이터 흐름은 다음과 같다.

```text
F6 selection.sha256 + selection.tier
    -> F10 policy input
    -> VerdictInput.baseline_sha256 + VerdictInput.baseline_tier
    -> F4 record_verdict()
    -> verdicts immutable history
```

## 4. 저장 모델과 마이그레이션

새 migration은 `verdicts.baseline_tier` nullable TEXT 컬럼을 추가한다. 컬럼의 `CHECK`
제약은 `NULL` 또는 세 Literal 값만 허용한다. 새 verdict INSERT에는 baseline SHA-256과
tier가 둘 다 있거나 둘 다 없는지 검사하는 trigger를 추가한다.

기존 DB에는 `baseline_sha256`이 있으나 tier를 추론할 수 없는 과거 행이 있을 수 있다.
마이그레이션은 이 행들을 삭제하거나 임의의 tier로 분류하지 않고 `baseline_tier=NULL`로
보존한다. 따라서 새 INSERT trigger와 `VerdictInput`은 짝 규칙을 엄격하게 적용하되,
persisted-state 검증은 `baseline_sha256`이 있고 tier가 `NULL`인 기존 행을 legacy
provenance로 허용한다. tier만 있고 baseline SHA-256이 없는 행과 알 수 없는 tier는
손상으로 취급한다.

verdict history update guard는 새 컬럼도 불변 값으로 비교한다. 허용되는 유일한 기존
verdict 변경인 `is_current: 1 -> 0`에서도 tier 값은 바뀔 수 없다.

## 5. 저장 경로와 오류 처리

`SQLiteArtifactStore.record_verdict()`는 DB 연결 전에 DTO를 다시 검증한다. 다음 입력은
`ValueError`로 실패하며 DB나 감사 이력에 변경을 남기지 않는다.

- 허용 목록 밖의 tier
- 문자열이 아닌 tier
- baseline SHA-256만 있거나 tier만 있는 새 DTO

유효한 tier는 verdict INSERT에 포함하고, 같은 transaction에서 저장된 행을 다시 읽어
입력과 일치하는지 확인한다. SQLite `CHECK`, 새 INSERT trigger, history update guard는
F4 외부에서 잘못된 SQL이 실행되더라도 새 이력이 계약을 위반하지 않게 한다.

## 6. 문서 변경

기존 F3/F4 설계의 `verdicts` 스키마, F6/F10 연동 계약, 완료 기준에
`baseline_tier`를 반영한다. README의 `VerdictInput` 예시는 baseline이 없을 때
`baseline_tier=None`을 명시한다. 기존 실행 계획은 완료 이력으로 유지하고, 이 확장을
위한 별도 구현 계획을 작성한다.

## 7. 테스트 전략

엄격한 red-green-refactor 순서로 다음을 검증한다.

- 모델: 세 Literal 값 수용, 잘못된 값과 baseline/tier 불일치 거부
- migration: 빈 DB와 기존 초기화 DB에서 반복 실행 가능, 기존 행은 tier `NULL` 보존
- store: 세 tier의 정확한 저장과 read-back 검증, 잘못된 DTO는 연결 전 거부
- schema: 허용되지 않은 tier와 새 INSERT의 짝 불일치 거부
- immutability: 저장된 tier의 UPDATE 거부와 current marker 전환 시 tier 보존
- corruption checks: tier-only 또는 알 수 없는 persisted tier를 fail-closed 처리
- 회귀: 전체 verdict, enforcement, integration 테스트와 lint/build 품질 명령 통과

## 8. 완료 기준

- F6가 제공하는 세 tier가 타입 변경 없이 `VerdictInput`에 들어간다.
- F10은 `sdist`를 다른 tier와 구분할 수 있다.
- F4가 새 verdict의 tier를 불변 이력으로 저장한다.
- baseline이 없는 경우는 두 필드가 모두 `None`이다.
- 기존 baseline 판정은 tier를 조작해 채우지 않고 그대로 마이그레이션된다.
- 잘못된 새 DTO와 직접 SQL INSERT가 상태나 감사 이력을 변경하지 않는다.
