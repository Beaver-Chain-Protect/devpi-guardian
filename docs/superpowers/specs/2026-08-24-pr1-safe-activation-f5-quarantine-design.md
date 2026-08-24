# PR #1 안전한 활성화와 F5 격리 저장소 설계

- 문서 상태: 승인된 F3/F4 보완 설계
- 작성일: 2026-08-24
- 대상 PR: #1 — F3/F4
- 범위: 신규 설치 activation gate, F5 미승인 Artifact 읽기 경로, CI, 독립 리뷰

## 1. 결정

PR #1은 기존 Artifact가 있는 devpi의 in-place 활성화나 migration/backfill을
지원하지 않는다. 이 릴리스가 지원하는 것은 Guardian을 처음 활성화하는 시점에
기존 Artifact 후보가 하나도 없는 devpi뿐이다.

Guardian은 이 전제와 맞지 않는 devpi에서 조용히 시작하거나 미판정 파일을 임시로
허용하지 않는다. 시작 단계에서 기존 Artifact 후보를 발견하면 tween 등록 전에
프로세스 시작을 실패시킨다. `--allow-legacy`, 미판정 pass-through, 경로별 예외와 같은
우회 옵션은 제공하지 않는다.

기존 devpi 지원은 별도 PR의 offline migration/backfill로 분리한다. 해당 도구가
완성되기 전에는 기존 인스턴스에 PR #1 플러그인을 활성화하지 않는다.

## 2. 지원 경계

### 지원

- devpi 자체 초기화는 끝났지만, Guardian 최초 활성화 snapshot에 기존 Artifact
  후보가 없는 primary 인스턴스
- 활성화 이후 발견되는 private 및 mirror Artifact의 fail-closed 수명 주기
- 활성화 이후 Guardian DB를 유지한 정상 재시작

### 미지원

- private release, cached mirror file, 또는 persisted release link가 이미 존재하는
  devpi에 Guardian을 처음 활성화하는 작업
- 기존 release를 자동 `ALLOW`로 간주하는 변환
- 온라인 상태에서 download를 허용한 채 수행하는 backfill
- Guardian DB를 삭제하거나 다른 devpi의 DB로 교체한 뒤의 자동 재등록
- PR #1 범위에서의 replica 간 Guardian 판정 복제

"신규 설치"는 devpi server directory가 새로 생성되었다는 뜻이 아니다. Guardian이
처음 활성화되는 일관된 devpi snapshot에 기존 Artifact 후보가 없다는 뜻이다.

## 3. Activation gate

### 3.1 영속 상태

Guardian SQLite에 단일 행 activation 상태를 둔다.

```text
guardian_activation
├── singleton             # 항상 1
├── devpi_uuid            # config.nodeinfo의 UUID
├── activated_at          # UTC RFC 3339
└── activation_version    # 최초 값 1
```

`devpi_uuid`는 같은 Guardian DB를 다른 devpi 인스턴스에 연결하는 실수를 차단한다.
행과 table의 형태가 잘못되었거나 UUID가 다르면 startup은 fail-closed한다. activation
행은 일반 요청이나 관리 명령으로 갱신·삭제하지 않는다.

### 3.2 최초 활성화 순서

플러그인은 `devpiserver_pyramid_configure`에서 다음 순서를 지킨다.

1. devpi node UUID와 XOM을 읽는다.
2. Guardian migration을 수행한다.
3. activation 행을 하나의 Guardian write transaction에서 조회한다.
4. 행이 없으면 devpi KeyFS read transaction의 한 snapshot에서 기존 Artifact 후보를
   탐색한다.
5. 후보가 하나라도 있으면 activation 행을 만들지 않고 명시적인 startup 오류로
   종료한다.
6. 후보가 없으면 현재 devpi UUID와 activation version을 기록한다.
7. activation 검증이 성공한 뒤에만 `VerdictReader`, metrics, enforcement tween을
   registry에 등록한다.

서버가 아직 요청을 받기 전이므로 빈 snapshot 확인과 activation 기록 사이에 외부
upload/download가 끼어들지 않는다. 운영 규칙대로 migration/activation owner는 한
프로세스뿐이어야 한다.

### 3.3 기존 Artifact 후보 판정

검사는 네트워크를 호출하거나 mirror를 refresh하지 않는다. 현재 KeyFS snapshot에
영속된 다음 자료를 검사한다.

- 삭제되지 않은 `STAGEFILE`과 `PYPIFILE_NOMD5` entry
- private 또는 mirror에 영속된 release link/simple-link 자료

release 관계를 확실히 분류하지 못하면 안전을 위해 기존 후보로 처리한다. tombstone과
Guardian 집행 대상이 아닌 것으로 확실히 증명된 자료만 제외할 수 있다. 검사는 첫
후보에서 중단할 수 있으며, 오류 메시지에는 credential, query, filename 또는 digest를
출력하지 않고 발견된 candidate 종류만 기록한다.

이 검사는 모든 Artifact가 판정 DB에 있다는 것을 매 startup 전수 대조하는 기능이
아니다. 활성화 이후의 미판정 Artifact는 정상적인 fail-closed 상태이며 F3가 차단한다.

### 3.4 재시작과 손실 처리

- activation 행과 devpi UUID가 일치하면 정상 재시작한다.
- activation 행이 없는데 기존 후보가 있으면 Guardian DB 손실 또는 legacy 활성화로
  간주하고 시작을 거부한다.
- activation 행의 UUID가 다르면 DB 오연결로 간주하고 시작을 거부한다.
- SQLite 잠금, 손상, migration 실패, KeyFS inventory 실패도 시작을 거부한다.

오류는 사용자가 다음 조치를 선택하도록 안내한다: 플러그인을 제거해 기존 devpi를
원상태로 실행하거나, 향후 제공될 offline backfill을 완료한 뒤 다시 활성화한다.
Guardian 보호를 약화하는 runtime flag는 안내하지 않는다.

## 4. 기존 devpi backfill의 후속 범위

후속 PR은 최소한 다음을 하나의 별도 설계로 해결해야 한다.

- offline 또는 write-frozen 일관 snapshot
- private release, cached mirror file, persisted mirror link의 inventory
- bytes 확보와 SHA-256/size 검증
- 아래 격리 CAS에 대한 idempotent 적재
- `release_mappings`와 `artifacts`의 재시작 가능한 등록
- backfill 중 추가되거나 삭제된 자료의 reconciliation
- 부분 실패 보고와 재개 checkpoint
- 모든 기존 Artifact가 terminal verdict에 도달하기 전 enforcement 활성화 금지
- dry-run, 운영자 확인, rollback/runbook

PR #1은 미래 backfill command 이름이나 미완성 bypass를 예약하지 않는다.

## 5. F5 미승인 Artifact 내부 경로

### 5.1 경계 선택

F5는 공개 devpi `+f`/`+e` URL로 미승인 bytes를 읽지 않는다. F3에 worker token,
header, query, loopback 예외 또는 관리자 bypass를 추가하지 않는다.

미승인 bytes의 유일한 내부 공급 경로는 deployment가 관리하는 별도 SHA-256
content-addressed quarantine directory다. devpi의 server directory와 Guardian
SQLite 파일은 Artifact bytes API가 아니다.

두 프로세스가 공유하는 설정은 하나의 absolute path다.

```console
GUARDIAN_QUARANTINE_DIR=/var/lib/devpi-guardian/quarantine
```

final object 경로는 SHA-256만으로 결정한다.

```text
<root>/objects/sha256/<digest[0:2]>/<digest[2:4]>/<64-char digest>
```

staging 파일은 `<root>/.incoming/` 아래에 생성하고 final object와 같은 filesystem을
사용한다. SQLite `origin_url`, filename, project, version 또는 사용자 입력을 filesystem
경로 구성에 사용하지 않는다.

### 5.2 publish 순서

private upload connector와 mirror discovery connector는 동일한 quarantine writer
계약을 사용한다.

1. `.incoming`에 exclusive temporary file을 연다.
2. bytes를 쓰면서 SHA-256과 size를 계산한다.
3. 예상 digest/size와 다르면 temporary file을 폐기하고 Artifact를 등록하지 않는다.
4. file을 flush/fsync하고, 기존 final object가 있으면 같은 bytes인지 검증한다.
5. final 경로로 atomic rename하고 필요한 parent directory를 fsync한다.
6. final object가 안전하게 publish된 뒤에만 `discover_artifact()`를 호출한다.

DB 등록이 실패한 뒤 남은 final object는 안전한 orphan이다. 아직 claim할 Artifact 행이
없으므로 F5가 분석하지 않는다. orphan 정리는 별도 운영 작업이며 PR #1에서 자동
삭제하지 않는다.

writer는 기존 final object를 덮어쓰지 않는다. symlink, hard-link 수 증가, directory
escape, 비정규 파일, 예상하지 않은 owner/mode를 거부한다. quarantine root는 공개
web server가 서빙하지 않으며 deployment-level 권한으로 writer와 F5 reader만 접근한다.

### 5.3 F5 read 순서

F5는 `claim_next()`로 받은 `ClaimedArtifact`의 SHA-256과 size만 사용해 final 경로를
계산한다.

1. 사전에 연 quarantine root directory descriptor를 기준으로 component별 `openat`
   또는 동등한 안전한 API를 사용한다.
2. `O_NOFOLLOW`를 적용하고 각 component와 final object가 예상 directory/regular file
   인지 `fstat`으로 검증한다.
3. file size가 claim의 `size_bytes`와 같은지 확인한다.
4. 같은 열린 file descriptor의 bytes를 streaming SHA-256으로 다시 계산한다.
5. digest가 claim과 일치한 경우에만 같은 descriptor를 rewind하여 analyzer에 전달한다.
6. 누락, 권한 오류, 형식 오류, size/digest 불일치는 verdict를 만들지 않고 fenced
   claim으로 `mark_analysis_error()`를 호출한다.

분석 중 file descriptor는 계속 열린 상태로 유지한다. 경로를 다시 열어 검증한 파일과
다른 파일을 분석하는 TOCTOU를 만들지 않는다. F5는 `origin_url`을 신뢰해 임의 URL을
fetch하거나 로컬 path로 해석하지 않는다.

### 5.4 생산자별 bytes 획득

- private upload는 devpi의 `devpiserver_on_upload` 시점에 검증된 `FileEntry` read
  stream을 quarantine writer로 복사한다.
- mirror Artifact는 discovery connector가 upstream 후보를 격리 저장소로 내려받고
  upstream hash가 있으면 함께 검증한다. 공개 Guardian `+f`/`+e` 경로로 재요청하지
  않는다.
- 이미 devpi에 존재하는 private/mirror 자료의 복사는 PR #1이 아니라 offline
  backfill 책임이다.

F5 구현 PR은 quarantine reader/writer를 공개 Python protocol 뒤에 두어 tests에서
실제 directory implementation을 검증한다. F4의 `ArtifactStore`와 Guardian SQLite
table을 bytes 저장소로 확장하지 않는다.

## 6. 실패 정책과 관찰 가능성

- activation 실패는 devpi readiness 이전의 fatal startup 오류다.
- 기존 후보 개수 전체를 세려고 startup을 오래 끌지 않는다. 첫 후보의 종류만
  bounded label로 기록한다.
- F5 quarantine 오류는 Artifact를 `ALLOW`로 만들 수 없다.
- 로그와 metric에는 digest 전체, filename, origin URL, local path, credential을 넣지
  않는다.
- activation 오류와 quarantine 오류의 사용자 메시지는 고정된 category를 사용한다.

## 7. CI

PR #1은 `.github/workflows/ci.yml`을 추가한다.

- pull request와 main push에서 실행한다.
- Python 3.11, 3.12, 3.13, 3.14 test matrix에서 locked dependency로 전체 pytest를
  실행한다.
- Python 3.11 quality job에서 `ruff format --check`, `ruff check`, `flake8 src tests`,
  `python -m build`를 실행한다.
- integration marker를 제외하지 않으며 real devpi subprocess tests도 포함한다.
- GitHub Actions concurrency로 같은 branch의 오래된 run을 취소한다.
- workflow permission은 `contents: read`만 부여한다.

필수 check 설정은 저장소 branch protection에서 별도로 적용한다. PR 설명에는 matrix와
quality check 이름을 명시해 reviewer가 required-check 설정을 검증할 수 있게 한다.

## 8. 독립 리뷰와 PR 상태

구현 후 작성자와 다른 fresh reviewer가 두 단계로 검토한다.

1. 이 보완 설계와 기존 F3/F4 설계에 대한 specification-compliance review
2. specification review가 통과한 뒤 security/code-quality review

Critical 또는 Important finding은 수정하고 해당 리뷰를 반복한다. controller는 reviewer
보고만 신뢰하지 않고 diff와 전체 quality command를 직접 확인한다. 리뷰 결과는 PR에
요약하며, GitHub review가 불가능하면 repository의 dated review artifact에 reviewer,
commit SHA, 실행한 command와 finding disposition을 남긴다.

PR #1은 다음 조건을 모두 충족해도 자동으로 Ready 전환하지 않고 Draft를 유지한다.

- activation gate와 회귀 테스트
- F5 quarantine 계약 문서와 구현 경계
- Python matrix와 quality CI
- 독립 spec/security review
- fresh full verification

Ready 전환은 별도의 사람 결정이다.

## 9. 테스트 전략

### Activation unit/integration tests

- 빈 devpi snapshot은 activation marker를 만들고 tween을 등록한다.
- 기존 private release, cached mirror entry, persisted mirror release link 각각은 최초
  activation을 거부한다.
- toxresult/document처럼 비-Artifact임이 확실한 entry는 gate 대상이 아니다.
- inventory가 분류하지 못하는 entry와 KeyFS 오류는 시작을 거부한다.
- 정상 재시작은 같은 marker를 재사용한다.
- marker 누락 + 기존 후보, malformed marker, 다른 devpi UUID, SQLite 오류는 시작을
  거부한다.
- 실패한 activation은 registry에 reader, metric, tween을 일부 등록하지 않는다.

### Quarantine contract tests

F5 구현 PR에서 다음을 검증한다.

- digest 경로의 결정성과 path traversal 불가
- digest/size mismatch 시 publish와 discovery가 모두 발생하지 않음
- atomic publish 이후에만 discovery 호출
- symlink/non-regular file/unsafe permission 거부
- 같은 digest의 idempotent publish와 다른 content 충돌 거부
- claim size/digest 재검증과 같은 descriptor 전달
- missing/corrupt object가 `mark_analysis_error()`로 끝나며 verdict는 기록되지 않음

### CI proof

- workflow syntax와 최소 permission을 정적 테스트한다.
- project의 Python 지원 범위와 CI matrix가 일치하는지 테스트한다.
- 전체 로컬 quality command와 GitHub Actions check를 모두 통과해야 한다.

## 10. 완료 기준

- 기존 Artifact 후보가 있는 devpi에서 Guardian 최초 활성화가 handler 등록 전에
  실패한다.
- 기존 자료를 허용하는 compatibility flag나 public worker bypass가 없다.
- 정상 활성화는 devpi UUID에 영속적으로 묶이고 DB 손실/오연결을 탐지한다.
- F5의 미승인 bytes 경로가 quarantine CAS 하나로 확정되어 있다.
- CI가 Python 3.11~3.14 전체 tests와 Python 3.11 quality/build를 실행한다.
- 독립 spec review와 security/code-quality review의 결과가 남는다.
- PR #1은 Draft 상태를 유지한다.
