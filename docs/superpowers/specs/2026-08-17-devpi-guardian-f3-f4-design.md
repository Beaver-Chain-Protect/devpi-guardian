# devpi-guardian F3·F4 설계

- 문서 상태: 승인된 설계
- 작성일: 2026-08-17
- 담당: 2번 — Enforcement·판정 저장소
- 범위: F3 직접 URL 차단, F4 Artifact 판정 저장소
- 구현 저장소: `devpi-guardian`

> **2026-08-24 activation/F5/CI 보완:** 기존 devpi 활성화 정책, F5 미승인
> Artifact 읽기 경로, CI와 독립 리뷰 조건은
> [`2026-08-24-pr1-safe-activation-f5-quarantine-design.md`](./2026-08-24-pr1-safe-activation-f5-quarantine-design.md)가
> 이 문서를 보완하며, 해당 항목에서는 새 문서가 우선한다.

> **2026-08-18 final resolver/metrics/fixture correction:** Protected
> `GET`/`HEAD` requests require at least one of `REQUEST_URI`, `RAW_URI`, or
> `RAW_PATH_INFO`; every present key must match the decoded identity. Literal
> route markers and canonical UTF-8 encoding are accepted. The only pip
> compatibility exception is the uppercase encoded fixed third route marker
> `/%2Bf/` or `/%2Be/`. Lowercase or double encoding, encoded slash, and
> encoded `+` in user, index, or tail are rejected. The in-process block
> recorder admits 4,096 normal series plus one fixed
> `cardinality_overflow` series, keeps incrementing existing keys, validates
> dimensions, and exposes only a bounded snapshot; external export is not
> part of F3/F4. The real subprocess harness and the official
> `pytest-devpi-server` fixture smoke test are both required evidence.

## 1. 목적

이 문서는 `devpi-guardian`의 직접 Artifact URL 우회를 차단하고, SHA-256 단위 판정을 영속적으로 저장하는 방법을 정의한다. 다른 작업자는 이 문서의 공개 인터페이스를 통해 F1·F2, F5, F7~F12를 연결한다.

성공 조건은 간단하다.

> 현재 유효 판정이 `ALLOW`인 SHA-256만 devpi 파일 다운로드 경로를 통해 전달한다.

미판정, 분석 중, `REVIEW`, `DENY`, `ERROR`, SHA-256 식별 실패, 판정 저장소 장애는 모두 fail-closed로 처리한다.

## 2. 범위와 비범위

### 포함

- `/+f/` 및 `/+e/` 직접 다운로드 집행
- `GET`, `HEAD`, PEP 658 `.metadata` 요청 통제
- SHA-256 기반 Artifact, Release Mapping, 자동 판정, 근거, 수동 override 저장
- 워커 claim과 상태 전이의 동시성 제어
- 승인, 차단, 승인 취소, 재분석을 위한 원자적 저장소 명령
- F2용 일괄 판정 조회
- F12 감사 기록을 동일 트랜잭션에 연결하는 확장점

### 제외

- Guardian Stage 및 Simple 링크 필터 구현: 1번 담당
- 분석 워커 프로세스와 관리자 API·CLI: 5번 담당
- 분석·탐지 로직: 3번과 4번 담당
- 정책 계산과 감사 이벤트 스키마: 6번 담당
- devpi 외부의 PyPI 직접 egress 차단: 배포 환경 책임
- 이미 시작된 응답 스트림을 승인 취소 시점에 강제로 중단하는 기능
- devpi replica 간 판정 DB 복제

## 3. 선택한 접근

P0는 devpi 플러그인이 등록하는 Pyramid tween과 별도 SQLite 판정 저장소로 구현한다.

- 직접 파일 뷰 실행 전에 tween이 판정을 조회한다.
- Pyramid tween은 main router보다 먼저 실행되므로 resolver는 `matched_route`, `matchdict`, `context`에 의존하지 않는다. `path_info`와 raw request target을 엄격히 분류하고, keyfs transaction 안에서 `registry["xom"].model.getstage(user, index)`로 stage를 조회한다.
- protected `GET`/`HEAD` raw request target은 `REQUEST_URI`, `RAW_URI`,
  `RAW_PATH_INFO` 중 하나 이상이 있어야 하며, 존재하는 모든 key는 decoded
  `path_info` identity와 일치해야 한다. Literal marker와 canonical UTF-8
  percent encoding만 허용하고, pip 호환을 위해 고정된 세 번째 route
  marker의 uppercase `/%2Bf/`·`/%2Be/`만 예외로 허용한다. lowercase 또는
  double encoding, encoded slash, user/index/tail 안의 encoded `+`는
  거부한다.
- `+f` entry가 아직 없는 mirror 요청은 pinned devpi view와 같은 프로젝트 metadata refresh만 수행한 뒤 entry를 한 번 재조회할 수 있다. Artifact 본문은 판정 전에 읽거나 전달하지 않으며, 재조회 후에도 canonical SHA-256 entry가 없으면 차단한다.
- SQLite는 별도 영구 볼륨의 `guardian.db`를 사용한다.
- 코어 PR 병합을 기다리지 않는다.
- 향후 devpi 코어가 파일 다운로드 필터 훅을 제공하면 F3 어댑터만 교체한다.

이 접근을 선택한 이유는 현재 devpi의 Simple 링크 생성에는 `get_simple_links_filter_iter`가 적용되지만 직접 파일 서빙 경로에는 같은 필터가 적용되지 않기 때문이다.

- [devpi Simple 링크 필터 적용](https://github.com/devpi/devpi/blob/main/server/devpi_server/model.py#L957-L983)
- [devpi 직접 `+f` 파일 서빙](https://github.com/devpi/devpi/blob/main/server/devpi_server/views.py#L1591-L1620)
- [`devpiserver_pyramid_configure` hookspec](https://github.com/devpi/devpi/blob/main/server/devpi_server/hookspecs.py#L81-L84)

`devpiserver_get_stage_customizer_classes`는 devpi 공식 소스에서 실험적 API로 표시되어 있다. 팀이 채택한 devpi-server 버전을 정확히 고정하고, 해당 버전에 대한 통합 테스트를 릴리스 조건으로 둔다.

## 4. 전체 구조

```text
pip / uv
   │
   ├─ Simple 조회 ──→ GuardianStage/F2
   │                       │
   │                       └─ VerdictReader.get_effective_decisions()
   │
   └─ /+f/, /+e/ GET·HEAD ─→ F3 Enforcement Tween
                                  │
                                  ├─ releasefile과 SHA-256 식별
                                  ├─ VerdictReader.get_effective_decision()
                                  ├─ ALLOW → 기존 devpi 파일 뷰
                                  └─ 나머지 → 404 또는 503

분석 워커/F5 ───────────────→ ArtifactStore 상태 전이
정책 엔진/F10 ──────────────→ ArtifactStore 자동 판정 기록
관리 API·CLI/F11 ───────────→ ArtifactStore 관리자 명령
감사 로그/F12 ──────────────→ 같은 쓰기 트랜잭션의 감사 이벤트
```

F2와 F3는 반드시 같은 `VerdictReader` 구현을 사용한다. 각자 별도 SQL이나 별도 판정 규칙을 구현하지 않는다.

## 5. F4 데이터 모델

### 5.1 테이블

| 테이블 | 책임 | 주요 필드 |
|---|---|---|
| `schema_migrations` | DB 스키마 버전 | `version`, `applied_at` |
| `artifacts` | Artifact와 분석 생명주기 | `sha256`, `size_bytes`, `state`, `discovered_at`, `updated_at`, `lease_owner`, `lease_expires_at`, `lease_token`, `last_error` |
| `release_mappings` | 패키지 파일과 SHA-256 연결 | `stage`, `project`, `version`, `filename`, `sha256`, `origin_url`, `discovered_at` |
| `verdicts` | 자동 판정의 불변 이력 | `id`, `sha256`, `decision`, `score`, `policy_version`, `analyzer_version`, `baseline_sha256`, `baseline_tier`, `is_current`, `created_at` |
| `evidence` | 판정 근거 | `id`, `verdict_id`, `rule_id`, `action`, `file_path`, `line`, `message`, `details_json` |
| `manual_overrides` | 관리자 승인·차단 이력 | `id`, `sha256`, `decision`, `actor`, `reason`, `created_at`, `expires_at`, `is_current` |
| `audit_events` | F12 감사 기록 | 6번이 정의하며 F4 트랜잭션에 참여 |

### 5.2 제약

- `sha256`은 소문자 64자리 16진수만 허용한다.
- `size_bytes`는 0 이상이다.
- `project`는 PEP 503 정규화 이름으로 저장한다.
- `version`과 `filename`은 원래 값을 보존한다.
- `origin_url`에서는 userinfo와 민감한 query parameter를 제거한다.
- 시간은 UTC RFC 3339 형식으로 저장한다.
- `SCANNING` claim에는 매번 새로 생성한 64자리 무작위 `lease_token`을 저장한다. 토큰은 로그나 외부 다운로드 URL에 노출하지 않는다.
- 자동 판정과 evidence는 갱신·삭제하지 않고 추가한다.
- DB trigger는 Artifact의 식별·크기·최초 발견 시각과 verdict/evidence 이력의 갱신·삭제를 거부한다. 관리자 명령은 writer lock 안에서 전체 evidence payload를 복사하지 않고 bounded row/count 검증만 수행한다.
- Artifact마다 `is_current=1`인 자동 판정과 수동 override는 각각 최대 하나다.
- 수동 override 대상 Artifact가 먼저 존재해야 한다.
- `DISCOVERED` 또는 `SCANNING` 중인 Artifact에는 수동 override를 만들지 않는다. 분석이 terminal state에 도달한 후에만 관리자가 개입한다.

### 5.3 상태 전이

```text
DISCOVERED
    │ claim_next
    ▼
SCANNING ───────────────→ ERROR
    │ record_verdict
    ├─→ ALLOW
    ├─→ REVIEW
    └─→ DENY

ALLOW / REVIEW / DENY / ERROR
    │ request_rescan
    └─→ DISCOVERED

SCANNING
    │ lease 만료 복구
    └─→ DISCOVERED
```

모든 쓰기 전이는 기대 상태를 조건에 포함하는 compare-and-swap으로 처리한다. 기대 상태가 다르면 `TransitionConflict`를 반환하며 호출자가 성공으로 간주하면 안 된다.

`claim_next`는 쓰기 트랜잭션 안에서 하나의 `DISCOVERED` 행만 `SCANNING`으로 변경하고 고유 `lease_token`을 포함한 `ClaimedArtifact`를 반환한다. 여러 워커가 동시에 호출해도 동일 SHA-256을 두 워커가 획득할 수 없다. 새 claim의 만료 시각은 writer lock을 획득한 시각보다 미래여야 한다.

`record_verdict`와 `mark_analysis_error`는 `ClaimedArtifact`를 다시 받아야 한다. 완료 전이는 `sha256`, `state=SCANNING`, `lease_owner`, `lease_expires_at`, `lease_token`, 미만료 조건을 모두 compare-and-swap에 포함한다. 만료되어 복구된 이전 claim의 늦은 결과는 같은 SHA-256이 다시 claim된 뒤에도 `TransitionConflict`로 거부한다.

### 5.4 자동 판정과 수동 override

관리자 결정은 원래 자동 판정을 수정하지 않는다. `manual_overrides`에 별도 이력으로 남긴다.

최종 판정 우선순위는 다음과 같다.

1. 현재 유효한 수동 `DENY`면 차단한다.
2. 현재 유효한 수동 `ALLOW`면 허용한다.
3. 현재 자동 판정이 `ALLOW`면 허용한다.
4. 그 외 모든 경우는 차단한다.

만료된 override는 조회 시점에 즉시 무효로 간주한다. 별도 만료 작업을 기다리지 않고 자동 판정으로 복귀한다.

재분석을 요청하면 현재 수동 override도 같은 트랜잭션에서 비활성화한다. 이전 승인 상태로 분석 중 Artifact가 노출되지 않도록 재분석 기간의 effective decision은 항상 차단이다.

## 6. 공개 저장소 인터페이스

구현 모듈의 권장 경계는 다음과 같다.

```text
src/devpi_guardian/
├── verdicts/
│   ├── invariants.py   # reader/store 공용 저장 상태 검증
│   ├── models.py       # DTO, enum, 검증
│   ├── reader.py       # VerdictReader
│   ├── store.py        # SQLiteArtifactStore
│   ├── errors.py       # 저장소 예외
│   └── sql/            # 순서가 고정된 패키지 내 SQL migration
└── enforcement/
    ├── resolve.py      # devpi entry → releasefile/SHA-256
    └── tween.py        # 요청 집행
```

### 6.1 읽기 계약

```python
class VerdictReader(Protocol):
    def get_effective_decision(
        self,
        sha256: str,
    ) -> EnforcementDecision: ...

    def get_effective_decisions(
        self,
        sha256s: Collection[str],
    ) -> Mapping[str, EnforcementDecision]: ...
```

`EnforcementDecision` 필드:

- `sha256: str`
- `allowed: bool`
- `effective_decision: ALLOW | DENY`
- `source: AUTOMATED | MANUAL_OVERRIDE | MISSING`
- `artifact_state: DISCOVERED | SCANNING | ALLOW | REVIEW | DENY | ERROR | MISSING`
- `policy_version: str | None`

누락된 SHA-256은 예외가 아니라 `allowed=False`, `source=MISSING` 결과로 반환한다. DB 연결·잠금·손상은 `StoreUnavailable` 예외로 구분한다.

### 6.2 쓰기 계약

```python
class ArtifactStore(Protocol):
    def discover_artifact(self, artifact, release) -> None: ...
    def claim_next(self, worker_id, lease_until) -> ClaimedArtifact | None: ...
    def recover_expired_claims(self, now) -> int: ...
    def record_verdict(self, claim, verdict, evidence) -> None: ...
    def mark_analysis_error(self, claim, error) -> None: ...
    def request_rescan(self, sha256, actor, reason) -> None: ...
    def set_manual_override(self, override) -> None: ...
    def revoke_manual_override(self, sha256, actor, reason) -> None: ...
```

주요 오류 타입:

- `InvalidSha256`
- `ArtifactNotFound`
- `TransitionConflict`
- `StoreUnavailable`
- `MigrationError`

호출자는 `TransitionConflict`를 무시하거나 무조건 재시도하지 않는다. 현재 상태를 다시 읽고 작업 의미에 맞게 결정한다.

## 7. SQLite 운영 규칙

- devpi 자체 DB와 분리된 영구 볼륨에 `guardian.db`를 둔다.
- `PRAGMA journal_mode=WAL`
- `PRAGMA foreign_keys=ON`
- `PRAGMA synchronous=FULL`
- `PRAGMA recursive_triggers=ON`
- 쓰기 전이는 `BEGIN IMMEDIATE`를 사용한다.
- `busy_timeout`을 설정한다.
- 프로세스와 스레드마다 별도 연결을 사용한다.
- reader는 current verdict와 current override를 별도 bounded query로 읽어 손상 DB의 중복 행을 판정 전에 제한한다.
- P0 first initialization에서는 정확히 하나의 startup/migration owner만
  empty DB에 대해 migration을 실행한다. owner가 readiness를 보고하기
  전에는 Guardian devpi instance를 여러 개 동시에 시작하지 않는다. 이후
  초기화된 DB로 시작하는 instance는 schema를 idempotently 검증한다.
- F5는 devpi plugin의 `ConnectionFactory` 객체를 공유하지 않는다.
  deployment가 관리하는 동일한 absolute DB path를 `--guardian-db`와 F5의
  독립적인 `ConnectionFactory` 생성에 각각 전달하고, owner readiness 이후
  F5를 시작한다.
- 승인과 취소의 즉시성을 위해 P0에서는 판정 cache를 두지 않는다.
- 운영 backup은 DB 파일 하나를 복사하지 말고 SQLite backup API 또는 checkpoint 후 일관된 snapshot을 사용한다.
- migration 실패 시 devpi-guardian을 준비 완료 상태로 올리지 않는다.

F3 tween은 plugin이 Pyramid registry에 설치한 thread-safe in-process block
recorder를 best effort로 호출한다. Recorder는 validated dimensions로
최대 4,096개의 normal series와 고정된 `cardinality_overflow` 1개만
유지하며, 이미 존재하는 series는 cap 이후에도 증가시킨다. Snapshot은
bounded copy이고 외부 metrics exporter는 이 범위에 포함되지 않는다.

F12는 다음 형태의 adapter를 제공한다.

```python
class AuditWriter(Protocol):
    def append_in_transaction(self, connection, event) -> None: ...
```

F4는 동일 SQLite connection과 transaction 안에서 `AuditWriter`를 호출한다. 감사 기록 실패 시 상태 변경도 rollback한다. 단위 테스트에서는 recording stub을 주입한다. 실제 통합 환경에서는 감사 writer가 없는 수동 변경 구성을 허용하지 않는다.

`discover_artifact`, `claim_next`, lease 복구, 자동 판정, 분석 오류, 승인·차단·취소·재분석을 포함한 모든 상태 변경이 감사 adapter를 호출한다. 시스템 작업의 actor는 worker ID 또는 고정된 service identity를 사용하고, reason에는 상태 전이 원인을 기록한다.

## 8. F3 직접 URL 집행

### 8.1 대상 요청

- 메서드: `GET`, `HEAD`
- 경로: `/{user}/{index}/+f/{relpath}`, `/{user}/{index}/+e/{relpath}`
- 객체: devpi link relation이 `releasefile`인 Artifact
- 파생 요청: `파일명.metadata`

POST toxresult 업로드, DELETE 관리 요청, 문서와 toxresult 파일은 기존 devpi 권한과 뷰에 맡긴다.

### 8.2 처리 순서

1. 요청 메서드와 devpi route를 확인한다.
2. `.metadata` suffix가 있으면 원본 Artifact entry path로 정규화한다.
3. devpi filestore entry와 link relation을 조회한다.
4. `releasefile`이 아니면 기존 handler로 넘긴다.
5. entry의 검증된 hash metadata에서 SHA-256을 읽는다.
6. SHA-256이 없거나 형식이 잘못되면 503으로 차단한다.
7. `VerdictReader.get_effective_decision`을 호출한다.
8. 결과가 정확히 `allowed=True`일 때만 기존 handler를 호출한다.

URL fragment, 사용자 header, filename에 포함된 값은 SHA-256 근거로 사용하지 않는다. 원격 mirror 파일이 아직 cache되지 않았더라도 사용자에게 bytes를 stream하기 전에 metadata로 판정해야 한다.

### 8.3 응답 정책

| 조건 | HTTP 결과 | 동작 |
|---|---:|---|
| 유효 `ALLOW` | 기존 devpi 응답 | handler 호출 |
| 미판정, `DISCOVERED`, `SCANNING` | 404 | 존재와 내부 상태를 숨김 |
| `REVIEW`, `DENY`, `ERROR` | 404 | 직접 URL 차단 |
| SHA-256 식별 실패 | 503 | fail-closed |
| DB 연결 실패·잠금 timeout·손상 | 503 + `Retry-After` | fail-closed |
| 비-releasefile | 기존 devpi 응답 | F3 범위 밖 |

상세 판정 사유는 응답 body나 header로 보내지 않는다. 내부 구조화 로그와 metric에는 route, SHA-256, effective decision, block category를 기록하되 URL credential과 민감 query는 기록하지 않는다.

승인 취소는 이후 시작되는 요청부터 반영한다. 이미 handler가 bytes 전송을 시작한 요청은 중단하지 않는다.

## 9. 다른 작업자 연결 방법

### 9.1 1번 — GuardianStage와 F2

- `SQLiteArtifactStore`가 노출하는 `VerdictReader`를 주입받는다.
- Simple 링크를 먼저 materialize하고 각 링크에서 SHA-256을 추출한다.
- `get_effective_decisions()`를 한 번 호출해 N+1 조회를 피한다.
- `decision.allowed`가 참인 링크만 yield한다.
- SHA-256이 없거나 형식이 잘못된 링크는 판정 조회 전에 제거한다.
- SQL, override 만료, 상태 우선순위를 `GuardianStage`에 복제하지 않는다.
- `devpiserver_pyramid_configure`에서 F3 tween을 등록하되 실제 집행 함수는 2번 모듈을 사용한다.
- tween은 `devpi_server.views.tween_keyfs_transaction` 아래에 등록하여 pre-routing resolver의 XOM model 조회가 일관된 read transaction 안에서 실행되게 한다.
- `root/pypi` 직접 접근도 F3을 통과하도록 파일 route 전체에 tween을 적용한다.
- PyPI 원본으로 직접 나가는 client egress는 배포 설정에서 차단한다. F3은 devpi를 거치지 않는 네트워크 요청을 막을 수 없다.

사용 예:

```python
decisions = verdict_reader.get_effective_decisions(link_sha256s)
for link, sha256 in links_with_sha256:
    yield decisions[sha256].allowed
```

### 9.2 3번·4번 — 분석기와 탐지 엔진

- DB를 직접 열지 않는다.
- 분석 결과를 `VerdictInput`과 `EvidenceInput` DTO로 반환한다.
- `EvidenceInput`의 공통 필드는 `rule_id`, `action`, `file_path`, `line`, `message`, `details`다.
- Source·Sink, 함수명, diff fragment처럼 규칙별로 달라지는 값은 JSON 직렬화 가능한 `details`에 둔다.
- Artifact SHA-256, baseline SHA-256, baseline tier, analyzer version을 항상 함께 전달한다. baseline이 없으면 baseline SHA와 tier는 모두 None이다.

### 9.3 5번 — 워커와 관리자 API·CLI

- 워커는 `claim_next()`로만 작업을 가져간다.
- 반환된 `ClaimedArtifact`는 작업 완료까지 보존하며 `worker_id`, `lease_expires_at`, `lease_token`을 바꾸거나 로그에 노출하지 않는다.
- 다운로드 후 실제 SHA-256이 claim의 SHA-256과 다르면 verdict를 기록하지 않고 `mark_analysis_error(claim, error)`를 호출한다.
- 분석 완료 시 같은 claim과 evidence 전체를 한 번의 `record_verdict(claim, verdict, evidence)` 호출로 저장한다.
- claim이 만료됐거나 `TransitionConflict`가 발생하면 결과를 버리고 새 claim을 가져온다. 이전 claim 결과를 새 claim으로 재사용하지 않는다.
- API·CLI는 SQLite에 직접 SQL을 실행하지 않는다.
- approve, block, revoke, rescan 요청은 actor와 비어 있지 않은 reason을 필수로 전달한다.
- HTTP 상태 매핑은 `ArtifactNotFound→404`, `TransitionConflict→409`, `StoreUnavailable→503`으로 통일한다.
- 워커에 F3 bypass token을 발급하지 않는다. upstream에서 후보를 받아 격리한 뒤 digest를 검증한다.

### 9.4 6번 — 정책 엔진과 감사 로그

- 정책 엔진은 `decision`, `score`, `policy_version`, `analyzer_version`, `baseline_sha256`, `baseline_tier`를 포함한 `VerdictInput`을 만든다. tier는 `same_tag`/`universal_wheel`/`sdist` 중 하나이며 baseline SHA와 함께 존재하거나 둘 다 None이다.
- 자동 판정을 저장할 때 기존 current verdict를 갱신하지 않고 새 verdict를 추가한다.
- F12는 `AuditWriter.append_in_transaction()` adapter와 `audit_events` migration을 제공한다.
- 감사 event에는 actor, action, sha256, 이전 effective decision, 새 effective decision, reason, policy version, analyzer version, 발생 시각을 포함한다.
- 같은 transaction에서 감사 event가 저장되지 않으면 승인·차단·취소·재분석도 실패해야 한다.

## 10. 완료 기준

### 10.1 F4 완료 기준

- migration을 빈 DB와 이미 초기화된 DB에 반복 실행할 수 있다.
- Artifact, release mapping, verdict, evidence, manual override가 재시작 후 유지된다.
- 잘못된 SHA-256과 금지된 상태 전이가 저장되지 않는다.
- 동일 Artifact를 동시에 claim하면 한 워커만 성공한다.
- lease 만료 claim이 안전하게 `DISCOVERED`로 복구된다.
- 만료·복구된 이전 claim의 늦은 verdict/error가 이후 claim을 완료하지 못한다.
- 자동 verdict와 evidence가 불변 이력으로 보존된다.
- current verdict와 current override가 Artifact당 하나만 존재한다.
- 수동 `ALLOW`와 `DENY`, 취소, 만료가 정해진 우선순위로 계산된다.
- 만료 시각 이후 첫 조회부터 override가 적용되지 않는다.
- 감사 기록 실패 시 판정 변경이 rollback된다.
- 새 automatic verdict는 F6의 세 tier 중 하나를 불변으로 보존하며, 기존 v1 baseline verdict의 unknown tier는 계속 NULL이다.
- F12의 persistent audit adapter integration은 별도 deliverable이다. F4
  현재 검증은 audit writer failure가 같은 transaction의 상태 변경을
  rollback하는지 증명한다.
- DB 연결 실패, 잠금 timeout, 손상을 `StoreUnavailable`로 반환한다.
- reader와 store가 동일한 저장 상태 검증기를 사용하며, 상태기계상 불가능하거나 형식이 손상된 current verdict/override는 허용 판정이나 일반 전이 충돌로 처리하지 않고 `StoreUnavailable`로 반환한다.
- F2의 일괄 판정 조회가 단건 조회와 동일한 결과를 반환한다.
- 판정 조회 P95가 목표 환경에서 100ms 이하이며 측정 조건과 결과가 기록된다.

### 10.2 F3 완료 기준

- `ALLOW`인 releasefile만 기존 devpi handler까지 도달한다.
- 미판정, `DISCOVERED`, `SCANNING`, `REVIEW`, `DENY`, `ERROR`는 `/+f/`와 `/+e/` 모두에서 전달되지 않는다.
- `GET`, `HEAD`, `.metadata`가 같은 판정을 사용한다.
- SHA-256 누락·변조·식별 실패 시 파일 bytes가 전달되지 않는다.
- DB 장애 중 파일 bytes가 전달되지 않는다.
- `root/pypi`와 cache 직접 URL을 사용해도 미승인 Artifact가 전달되지 않는다.
- uv lockfile의 직접 URL로 우회할 수 없다.
- 승인 직후 같은 SHA-256 다운로드가 성공한다.
- 승인 취소 이후 새 요청은 즉시 차단된다.
- 승인된 이전 버전은 유지되고 미승인 신규 버전만 차단된다.
- 비-releasefile과 기존 관리 요청 동작을 깨뜨리지 않는다.
- devpi 재시작 후에도 동일 판정이 집행된다.
- 동일 SHA-256 동시 요청에서 미승인 통과가 0건이다.

### 10.3 필수 테스트 묶음

- F4 repository 단위 테스트
- F3 resolver 및 tween 단위 테스트
- 실제 SQLite 파일을 사용하는 transaction·재시작 테스트
- `pytest-devpi-server` 기반 `/+f/`, `/+e/`, Simple API 통합 테스트
- pip 정확한 버전 설치 테스트
- uv 및 uv lockfile 직접 URL 테스트
- DB 잠금·중단·재연결 장애 테스트
- 승인·취소·만료 동시성 테스트
- 판정 조회 성능 측정
- real subprocess harness와 `pytest-devpi-server` official fixture smoke
  proof를 모두 포함한다.

## 11. 확정된 구현 기준

구현 저장소는 `/Users/esc/Desktop/BCP/devpi-guardian`에 생성했다. 구현과 통합 테스트는 다음 기준으로 고정한다.

- devpi-server: `6.20.3` 정확 버전
- Python: `3.11`~`3.14`
- 패키지 구조: `src/devpi_guardian`
- 테스트와 품질 도구: pytest, pytest-devpi-server `1.8.0`, Ruff, Flake8, uv
- 판정 DB 설정: `devpi-server --guardian-db PATH`
- 기본 DB 위치: 옵션을 생략하면 devpi server path 아래 `guardian/guardian.db`
- 운영 배포: `guardian.db`와 WAL 관련 파일이 유지되는 별도 영구 볼륨 사용

실행 가능한 작업 순서와 각 단계의 테스트·커밋 기준은
`docs/superpowers/plans/2026-08-17-f3-f4-enforcement-verdict-store.md`에 둔다.
