# PR #5/#9 안전 통합 설계

- 문서 상태: 승인된 통합 설계
- 작성일: 2026-08-25
- 기준 main: `3d210395dc806cc0420bda97c6e6e8a8dc1a1883` (PR #1 merge)
- 기능 원본: PR #5 `22bc029e584af43e6c79b72a3d6fcef35f49f05f`, PR #9
  `52593ae444f416625a0e96f0a4874bc30987ce8d`
- 선행 계약:
  [`2026-08-24-pr1-safe-activation-f5-quarantine-design.md`](./2026-08-24-pr1-safe-activation-f5-quarantine-design.md)

## 1. 결정

PR #5와 PR #9는 main에 직접 merge하지 않는다. 두 PR의 최종 기능을 PR #1이 반영된
main에서 새 통합 브랜치로 선택 이식한다. merge commit 여덟 개를 재생하거나 충돌 난
최종 tree를 그대로 채택하지 않고, 기능 단위의 production code와 tests를 가져온 뒤
PR #1의 activation, public download enforcement, SQLite history, claim fencing 계약에
맞게 통합한다.

PR #9은 F5 worker의 devpi thread-pool 등록과 F11 production provider wiring을 유효한
기능 원본으로 사용한다. 다만 PR #9이 PR #5 위에서 clean하다는 사실은 PR #1이 반영된
main과의 호환성을 의미하지 않는다. migration, startup ordering, quarantine I/O와 locked
dependency는 이 설계에서 다시 확정한다.

## 2. 검토한 접근

### 선택: 최신 main에서 기능 단위 선택 이식

- PR #1의 보안 경계와 이력을 기준으로 유지한다.
- PR #5/#9의 독립 기능을 작은 단위로 가져와 각 단계마다 red-green 검증한다.
- migration 번호와 plugin startup을 하나의 최종 구조로 설계할 수 있다.
- 원본 PR의 merge noise와 criss-cross ancestry를 main history에 넣지 않는다.

### 배제: PR #5에 PR #9을 merge한 뒤 main에 직접 merge

- PR #1과 동일한 7개 direct conflict가 남는다.
- 충돌 해결만으로 quarantine 보안 계약이나 activation-before-side-effects 순서가
  자동으로 충족되지 않는다.
- PR #5의 merge commit들이 이미 여러 feature branch를 중복 통합해 history와 책임
  경계를 흐린다.

### 배제: PR #5/#9 commit 전체 cherry-pick

- DB migration과 `plugin.py`를 구버전 전제로 덮어쓸 위험이 있다.
- 단일 feature commit에도 서로 다른 F5/F11/F6/F7 변경이 섞여 있어 기능별 검증이
  어렵다.

## 3. 통합 범위

통합 대상은 PR #5 최종 tree와 PR #9의 보완분에 존재하는 다음 기능이다.

- F5 quarantine worker, discovery queue, analysis pipeline, cooldown, durable handoff
- F6/F7 baseline selection, release comparison과 diff evidence
- F10/F12 policy engine, append-only audit chain과 startup verification
- F11 admin API/CLI와 production providers
- PR #9의 worker thread registration, health providers, diff/audit/baseline/policy wiring

PR #1의 다음 구현은 기준이며 PR #5/#9 버전으로 되돌리지 않는다.

- 모든 devpi `+f`/`+e` 요청에 대한 F3 enforcement
- `VerdictReader`의 effective decision과 손상 데이터 fail-closed 처리
- verdict/evidence/override history와 fenced worker transitions
- 신규 설치 activation gate와 legacy Artifact inventory 거부
- worker용 public URL bypass 부재
- Python 3.11~3.14 CI와 quality job

기존 devpi offline migration/backfill은 계속 별도 후속 범위다.

## 4. SQLite migration과 데이터 소유권

최종 migration 순서는 다음과 같이 고정한다.

1. `001_initial.sql`
2. `002_baseline_tier.sql`
3. `003_guardian_activation.sql`
4. `004_artifact_cooldown.sql`
5. `005_audit_events.sql`
6. `006_baseline_overrides.sql`

PR #5/#9의 `003_artifact_cooldown`, `004_audit_events`, `005_baseline_overrides`는 각각
004, 005, 006으로 재번호화한다. `MIGRATIONS` 목록, package data tests와 schema version
assertion도 같은 순서를 사용한다.

모든 feature는 `ArtifactStore`, `VerdictReader`, `AuditWriter`의 public interface를
사용한다. admin provider, baseline selector, policy engine과 worker는 Guardian table에
임의 SQL을 실행하지 않는다. 기존 verdict/evidence/override/audit 불변성과 transaction
경계는 유지한다.

## 5. Startup과 runtime wiring

`devpiserver_pyramid_configure`의 side-effect 순서는 다음과 같다.

1. 설정값을 읽고 형식과 보안 경계를 검증한다.
2. Guardian SQLite migration을 실행한다.
3. audit chain이 존재하면 무결성을 검증한다.
4. devpi UUID와 한 KeyFS snapshot으로 activation을 검증하거나 최초 activation한다.
5. activation 성공 후 reader, store, audit writer, discovery queue, policy와 metrics를
   생성한다.
6. primary에서만 F5 worker를 devpi thread pool에 등록한다. replica에서는 worker를
   시작하지 않는다.
7. F11 production providers와 admin routes를 등록한다.
8. 마지막으로 F2/F3 registry state와 enforcement tween을 게시한다.

1~4 단계가 실패하면 worker thread, registry state, admin route, tween을 하나도 등록하지
않는다. 이후 단계의 필수 dependency 생성이 실패해도 부분적으로 요청을 받지 않도록
startup을 실패시킨다. worker는 activation보다 먼저 실행될 수 없다.

## 6. Quarantine CAS

PR #1의 F5 quarantine 계약을 구현의 권위 있는 기준으로 사용한다.

- root는 사용자가 명시한 absolute path이며 devpi server directory와 public route 밖의
  전용 directory여야 한다.
- final object는 `<root>/objects/sha256/<d0d1>/<d2d3>/<64-hex-digest>`에 저장한다.
- `.incoming`과 final object는 같은 filesystem에 둔다.
- root와 parent component는 symlink가 아니어야 하며 owner/mode가 안전하지 않으면
  startup 또는 I/O를 거부한다.
- publish는 exclusive staging file, streaming digest/size 검증, fsync, atomic
  no-overwrite publish, parent fsync 순서를 지킨다.
- 기존 object는 regular file, link count, owner/mode, size와 digest가 모두 일치할 때만
  idempotent 성공으로 처리한다.
- reader는 component별 no-follow open과 `fstat`을 사용한다. 검증한 동일 file
  descriptor를 rewind해 analyzer에 전달하고 분석 종료까지 유지한다.
- 누락·손상·권한·경로 오류는 `ALLOW`를 만들지 않고 fenced
  `mark_analysis_error()`로 끝난다.
- `origin_url`, filename, project와 version은 filesystem path 생성에 사용하지 않는다.

기본값으로 DB 인접 상대 경로를 자동 선택하지 않는다. quarantine을 활성화하는
primary는 명시적인 absolute root 없이는 worker를 시작하지 못한다.

## 7. F5/F6/F7/F10/F11/F12 데이터 흐름

Artifact discovery는 검증된 quarantine object publish 뒤에만 `discover_artifact()`를
호출한다. worker는 claim의 digest와 size로 object를 열고 검증한 stream을 analyzer에
전달한다. 분석 결과, baseline 선택과 release diff를 policy engine에 전달하고 verdict,
evidence, audit transition을 기존 fenced transaction 계약으로 기록한다.

F11은 production providers를 통해서만 다음을 노출한다.

- worker/queue health
- verdict와 evidence 조회 및 승인·취소·재분석 명령
- baseline eligibility/history와 override
- release diff evidence
- policy configuration/evaluation 결과
- audit event와 chain verification 상태

관리 API는 quarantine bytes를 직접 반환하거나 public F3 bypass를 발급하지 않는다.
provider 오류는 기존 F11 HTTP error mapping을 따르고 credential, origin URL, local path,
전체 digest를 로그에 남기지 않는다.

## 8. 의존성 및 패키징

PR #9의 production plugin이 F6 baseline Artifact reader에 주입하는
`requests.Session`을 사용하므로 `requests>=2.32,<3`를 direct runtime dependency로
유지한다. `pyproject.toml` 변경과 같은 commit에서 `uv lock`을 실행해 `uv.lock`의
project dependency metadata를 갱신한다.

어느 경우든 `uv sync --locked --extra test`가 clean checkout에서 성공해야 한다. 모든
새 package, SQL migration, JSON schema와 console entry point가 sdist/wheel에 포함되는지
package tests와 `uv build`로 검증한다.

## 9. 테스트 전략

각 통합 단위는 focused failing test를 먼저 추가하고 expected failure를 관찰한 뒤 최소
production change로 통과시킨다.

- migration: 빈 DB, v2→v6, v3 activation DB→v6, 반복 실행과 unknown future version
- startup: activation 실패 시 zero side effects, 성공 시 worker/admin/tween 순서,
  replica worker 미등록, audit corruption fail-closed
- quarantine: deterministic path, traversal 거부, symlink/non-regular/hard-link/unsafe
  mode 거부, atomic no-overwrite race, idempotent publish, same-descriptor analysis,
  corrupt/missing object error transition
- worker: discovery/claim/cooldown/fencing/restart handoff와 production thread lifecycle
- baseline/policy/audit/admin: provider wiring, evidence persistence, override history,
  chain tamper detection과 HTTP/CLI mapping
- integration: real devpi private upload와 mirror path가 public bypass 없이 quarantine,
  verdict, `+f`/`+e` enforcement까지 이어짐

최종 검증은 locked install, 전체 pytest, Ruff format/check, flake8, build를 포함한다.
GitHub Actions의 Python 3.11, 3.12, 3.13, 3.14 test matrix와 Python 3.11 quality job이
모두 성공해야 한다.

## 10. 독립 리뷰와 전달 방식

구현 branch는 PR #5나 #9에 force-push하지 않는다. 새 integration PR을 main 대상으로
만든다. 작성자와 다른 reviewer가 먼저 이 설계의 specification compliance를 검토하고,
통과 후 security/code-quality review를 수행한다. Critical과 Important finding은 모두
수정하고 동일 단계의 재검토를 통과해야 한다.

통합 PR 설명에는 다음 provenance를 남긴다.

- PR #5와 PR #9에서 이식한 기능과 원본 commit SHA
- 직접 merge하지 않은 이유
- migration 재번호화와 startup ordering 결정
- quarantine hardening 차이
- local verification과 GitHub Actions 결과

PR #5와 PR #9은 새 integration PR이 main에 merge된 뒤 superseded로 정리한다. 새 PR이
검증되기 전에는 두 원본 PR을 main에 merge하지 않는다.

## 11. 완료 기준

- PR #5/#9 기능이 PR #1 보안 경계를 약화하지 않고 최신 main 위에서 동작한다.
- schema v6 migration이 신규 DB와 PR #1의 activation DB 모두에서 재실행 가능하다.
- activation과 audit 검증 전에 worker, admin, reader, metrics, tween side effect가 없다.
- quarantine CAS가 absolute dedicated root, no-follow, atomic no-overwrite와
  same-descriptor 분석 계약을 충족한다.
- public `+f`/`+e`는 effective `ALLOW` 외에는 계속 fail-closed한다.
- clean checkout의 locked dependency, Python 3.11~3.14 CI, quality, build와 real devpi
  integration tests가 통과한다.
- 독립 spec/security review의 Critical·Important finding이 0개다.
- main에는 PR #5/#9 직접 merge가 아니라 새 integration PR만 merge된다.
