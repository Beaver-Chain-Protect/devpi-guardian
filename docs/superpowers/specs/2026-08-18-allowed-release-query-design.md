# Allowed Release Query Design

## 목적

F6 Trusted Baseline 작업자가 SHA-256을 미리 알지 못해도 프로젝트 이름으로
현재 사용 가능한 정상 release 목록을 조회할 수 있게 한다. 이 조회는 F2와 F3가
사용하는 것과 동일한 effective-decision 규칙을 사용해야 한다.

## 공개 계약

`VerdictReader`에 다음 메서드를 추가한다.

```python
def list_allowed_releases(
    self,
    project: str,
) -> tuple[AllowedRelease, ...]: ...
```

반환 모델은 불변 값 객체다.

```python
@dataclass(frozen=True, slots=True)
class AllowedRelease:
    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    origin_url: str
```

- 입력 `project`는 non-empty built-in `str`만 허용하고 PEP 503 규칙으로
  정규화한다.
- 모든 devpi stage의 일치하는 release를 조회한다. stage가 다른 동일 프로젝트를
  구분할 수 있도록 `stage`를 반드시 반환한다.
- 현재 effective decision이 정확히 `ALLOW`인 release만 반환한다. 자동 ALLOW,
  유효한 수동 ALLOW, 수동 DENY, 만료된 override의 우선순위는 기존
  `get_effective_decision()`과 같다.
- 하나의 SHA-256에 여러 release mapping이 있으면 각 release mapping을 별도
  결과로 반환한다.
- 결과는 `(stage, version, filename, sha256, origin_url)` 순서로 결정론적으로
  정렬한 tuple이다. 일치하는 ALLOW release가 없으면 빈 tuple이다.

## 조회 구조와 일관성

`SQLiteVerdictReader`는 하나의 SQLite read transaction과 하나의 `as_of` 시각
안에서 다음을 수행한다.

1. 정규화된 project에 해당하는 immutable `release_mappings`를 조회한다.
2. 관련 artifact, current verdict, current manual override를 bounded query로 읽는다.
3. 기존 `validate_persisted_state()`를 사용해 각 SHA-256의 effective decision을
   계산한다.
4. effective decision이 `ALLOW`인 SHA-256의 release mapping만 반환한다.

별도 release query 뒤에 SHA별 공개 reader 메서드를 반복 호출하거나 SQL view에
판정 우선순위를 다시 작성하지 않는다. 전자는 snapshot race를 만들고 후자는
F2/F3/F6 판정 규칙을 갈라놓기 때문이다.

대량 프로젝트에서도 SQLite parameter 제한과 메모리 사용이 제한되도록 기존
chunk 크기를 재사용한다. current verdict 또는 current override가 중복되거나
artifact/release 데이터가 계약을 위반하면 일부 결과를 반환하지 않고
`StoreUnavailable`로 fail closed 한다.

## `origin_url` 계약

`origin_url`은 로컬 filesystem 경로가 아니라 artifact를 받기 위한 절대 HTTP(S)
URL이다. F5 discovery 연결자는 `ReleaseInput.origin_url`에 해당 release의 canonical
devpi `+f` 또는 `+e` 다운로드 URL을 제공해야 한다.

F4는 저장 시 URL에서 userinfo, query, fragment를 제거한다. URL의 원격 콘텐츠를
직접 내려받아 SHA-256을 재검증하지는 않으므로, F6는 이 값을 신뢰 우회 경로로
쓰지 않고 devpi를 통해 HTTP 요청해야 한다. 그러면 기존 Guardian enforcement가
다운로드에도 동일하게 적용된다.

## 오류 처리

- 잘못된 project 입력은 DB 연결 전에 `ValueError`로 거부한다.
- SQLite 오류나 저장 상태 손상은 DB 경로만 포함하는 `StoreUnavailable`로
  변환하며 원래 예외는 cause로 보존한다.
- 유효한 결과가 없다는 사실은 오류가 아니며 빈 tuple을 반환한다.

## 테스트와 문서

- project 정규화, multi-stage, 다중 mapping, deterministic ordering을 검증한다.
- 자동 ALLOW와 수동 ALLOW를 포함하고 DENY, REVIEW, ERROR, 진행 중 상태, 유효한
  수동 DENY를 제외한다.
- 만료 override와 조회 시각 경계를 기존 판정 규칙과 동일하게 검증한다.
- 중복 current history, malformed persisted row, SQLite failure가 fail closed 되는지
  검증한다.
- 큰 release 집합이 chunk 경계를 넘어도 정확하고 bounded하게 동작하는지
  검증한다.
- README에 F6 호출 예제와 `origin_url` 연결 계약을 추가한다.

## 범위 밖

- version을 PEP 440 순서로 비교하거나 baseline을 자동 선택하지 않는다.
- stage 필터나 pagination을 새 공개 옵션으로 추가하지 않는다.
- artifact를 직접 다운로드하거나 파일을 여는 기능은 제공하지 않는다.
- schema migration이나 release mapping 쓰기 계약은 변경하지 않는다.
