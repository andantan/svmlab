# 남은 작업

원칙: 1 instruction = 1 endpoint. 여러 instruction을 묶는 batch/vault류는 이 저수준
API 원칙에서 벗어나므로 전부 뒤로 미룸.

- **완료**: System Program, PDA 파생, SPL Token classic (batch 제외 전부),
  Associated Token Account (derive/validate/recover-nested 포함),
  Compute Budget Program (4개 instruction 전부 — set-compute-unit-limit,
  set-compute-unit-price, request-heap-frame,
  set-loaded-accounts-data-size-limit — 전부 devnet-confirmed)

- **보류 (원칙에 안 맞아서 뒤로 미룸)**
  - `token/batch` — 여러 Token instruction을 하나에 중첩
  - Vault 커스텀 프로그램 — 자체 배포 프로그램, 코어 프로그램의 단일 instruction이 아님

- **다음 후보 (원칙에 맞음, 순서 미정)**
  - Token-2022 `metadata-pointer` + `spl-token-metadata-interface` — 단일
    instruction 5개(Initialize/UpdateField/RemoveKey/UpdateAuthority/Emit),
    기존 Token-2022 인프라 재사용 가능

- **작은 후속 작업 (나중에)**
  - `getRecentPrioritizationFees` RPC 래퍼 — `svm/cluster/...`에 읽기 전용으로 추가.
    "얼마 낼지"가 아니라 "요즘 시세가 얼마인지" 알려주는 것 (fee 계산 자체는
    이미 `getFeeForMessage`로 정확히 되고 있어서 급하지 않음)

- **더 뒤 (더 무거운 선행 작업 필요)**
  - Address Lookup Table — versioned(v0) transaction 지원이 먼저 필요
  - Metaplex Token Metadata 프로그램 — Borsh 직렬화를 새로 배워야 함
  - Token-2022 나머지 확장 (transfer-fee, non-transferable, permanent-delegate,
    transfer-hook, confidential-transfer 등)
  - Stake, Vote, Loader/deployment
