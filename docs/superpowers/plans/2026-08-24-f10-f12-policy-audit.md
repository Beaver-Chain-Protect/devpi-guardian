# F10/F12 implementation plan

1. Add failing F10 contract, precedence, coverage, score, and version tests.
2. Implement the immutable policy configuration, assessment, and engine; run focused
   policy and worker regression tests.
3. Add failing migration and audit writer tests.
4. Implement migration 004, the transactional writer, hash-chain verifier, and public
   audit exports; run focused database/audit/store tests.
5. Add failing plugin integration tests, wire F12 into F11 mutation readiness, and run
   administrator/plugin regression tests.
6. Add handoff documentation and a release-note fragment.
7. Run the full test, format, lint, lock, and build matrix and review the complete diff.
