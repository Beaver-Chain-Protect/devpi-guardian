# README PR 보강 설계

## 목적

`feature/f3-f4-enforcement-store` 브랜치를 GitHub PR로 게시하기 전에,
처음 보는 작업자가 저장소의 구성과 완성된 F3/F4 기능을 README 상단에서
빠르게 파악할 수 있게 한다.

## 변경 범위

- `README.md`의 기존 handoff, 운영, 보안, 성능, 완료 기준은 유지한다.
- 소개 다음에 `Implemented features`를 추가해 구현 결과를 기능 단위로
  요약한다.
- `Repository structure`에는 최대 3단계의 핵심 경로만 표시한다.
- 폴더 트리에는 생성물, cache, virtual environment, 개별 테스트 파일 목록을
  넣지 않는다.
- 제품 코드, 테스트 동작, 승인된 F3/F4 설계는 변경하지 않는다.

## README 구성

1. 프로젝트 소개
2. 구현된 기능
   - fail-closed 직접 다운로드 enforcement
   - SHA-256 기반 SQLite 판정 저장소
   - claim fencing, 자동 판정, evidence, 관리자 override와 rescan
   - devpi plugin, metrics, 실제 pip/uv 통합 검증
3. 핵심 저장소 구조
   - `src/devpi_guardian/enforcement`
   - `src/devpi_guardian/verdicts`
   - `tests/enforcement`, `tests/verdicts`, `tests/integration`
   - `docs/superpowers`, `news`
4. 기존 handoff와 운영 문서

## 정확성 기준

- 기능 명칭과 상태 전이는 현재 공개 API 및 승인 설계와 일치해야 한다.
- F12 영속 감사 adapter는 별도 deliverable임을 유지한다.
- raw-path, metric cap, 단일 최초 migration owner 같은 운영 경계를 축약 과정에서
  누락하거나 완화하지 않는다.
- Markdown 링크와 tree가 실제 경로를 가리켜야 한다.

## 게시 절차

README 변경을 별도 커밋하고 전체 테스트·lint·build를 재검증한다. 현재 feature
브랜치를 `git@github.com:Beaver-Context-Protocol/devpi-guardian.git`에 push한 뒤,
원격 기본 브랜치를 대상으로 draft PR을 생성한다.
