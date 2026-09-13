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

- **진행 중: Token-2022 확장**

  인프라 완료:
  - `core.ExtensionType` 27개 값 전부 선언 + `ParseExtensionType`(이름→값)
  - `core.ExistingExtensionTypes` — 계좌 TLV 영역 파싱해서 기존 확장 목록 뽑기
  - `core.(*token).GetAccountDataSize` + `token/extensions/get-account-data-size`
    (읽기 전용, simulate 기반, devnet-confirmed) — 확장 조합의 정확한 계좌 크기를
    프로그램한테 직접 물어봄, 하드코딩 안 함
  - `core.(*token).Reallocate` — 계좌 리사이즈만 함, 확장을 켜는 게 아님
    (확인됨: TLV 헤더/데이터 안 씀, 그냥 공간만 늘림)
  - 15개 확장 패밀리의 서브인스트럭션 discriminant 전부 상수로 선언
    (transfer-fee, confidential-transfer, default-account-state, memo-transfer,
    interest-bearing, cpi-guard, transfer-hook, confidential-transfer-fee,
    metadata-pointer, group-pointer, group-member-pointer, confidential-mint-burn,
    scaled-ui-amount, pausable, permissioned-burn) — 전부 upstream 소스로 확인,
    아직 builder/엔드포인트는 없음

  `reallocate/*` — 27개 중 진행 상황 (라우트: `extensions/<타입>/reallocate`):
  - [x] `transfer-fee-config` — 로직 완료, mint 전용 타입을 계좌에 넣는 조합이라
    항상 실패하는 게 정상 동작임을 devnet에서 확인 (`ExtensionTypeMismatch`,
    Custom 20 — 우리 핸들러의 GetAccountDataSize 사전검증 단계에서 걸림)
  - [x] `transfer-fee-amount` — devnet-confirmed, 계좌 쪽 진짜 확장이라 정상
    성공. raw 바이트로 TLV(type=2, len=8) 확인, `space: 182`
    (165+1+ImmutableOwner헤더4+TransferFeeAmount헤더4+데이터8, ATA라
    ImmutableOwner도 자동으로 붙어있었음)
  - [ ] 나머지 25개, 하나씩 순서대로 (스크립트로 일괄 생성 안 함, 각각 개별 작업)
  - `token_metadata`(19)만 가변 길이라 GetAccountDataSize 흐름이 다름 —
    name/symbol/uri 받아서 Borsh 공식으로 직접 계산

  mint 확장 lifecycle (opcode 26, TransferFeeExtension) — 진행 상황:
  - [x] `token/extensions/mint/data-size` — mint에 확장을 붙일 때 필요한 크기를
    클라이언트에서 직접 계산 (온체인에 mint 사이즈 계산해주는 instruction 자체가
    없어서 GetAccountDataSize 방식 불가 — `extensionTypeDataLen` 표 실사용,
    devnet 실제 계좌 바이트로 교차검증 완료). **버그 하나 잡음**: 확장이 있는
    mint은 82바이트가 아니라 165바이트(holder 계좌 길이)로 먼저 패딩된 뒤
    AccountType+TLV가 시작됨 — 처음에 82를 base로 써서 83바이트 부족한 크기를
    계산했고, 실제 devnet에서 `InvalidAccountData`로 확인 후 수정
  - [x] `extensions/transfer-fee-config/initialize` (sub 0) — devnet-confirmed,
    278바이트 mint에 실제로 TransferFeeConfig TLV(type=1, len=108)가 정확히
    박히는 것까지 raw 바이트 파싱해서 검증 완료. `COption<Pubkey>` 타입이지만
    실제 인코딩은 1바이트 태그(계정 데이터의 4바이트 태그 COption과 다름) —
    `pack_pubkey_option` 소스로 확인, 기존 `appendPubkeyOption` 헬퍼 그대로 재사용
  - mint에 확장 넣으려면 `create-mint`(고정 82바이트) 대신
    `system/create-account`(0바이트) → `system/allocate`(계산된 크기로) →
    `system/assign`(owner를 Token-2022로) 3단계를 거쳐야 함 — `create-mint`는
    확장 없는 mint 전용
  - [x] `extensions/transfer-fee-config/set` (sub 5, 라우트는 `/set`으로 축약) —
    devnet-confirmed, RPC parsed 로그에서 `type: "setTransferFee"`,
    `transferFeeBasisPoints: 300`, `maximumFee: 2222`까지 정확히 확인
  - [x] `extensions/transfer-fee-config/transfer` (sub 1,
    TransferCheckedWithFee) — devnet-confirmed. **`fee`는 요청 필드가 아니라
    서버가 자동 계산** — 프로그램이 mint의 TransferFeeConfig로 직접
    재계산해서 정확히 일치해야만 통과(`FeeMismatch`, 상한이 아니라 정확히
    일치). `core.DecodeTransferFeeConfig`(mint TLV 값 디코드, MaybeNull<Address>
    = 전부 0이면 None인 32바이트 고정폭, COption 아님 — 공식 확인함) +
    `getEpochInfo` RPC 신규 추가 + `core.TransferFeeConfig.CalculateFee`
    (ceil(amount×basis_points/10000), maximum_fee 상한)로 계산. 1000개 전송에
    500bps 요율로 수수료 50 정확히 계산됨, raw 바이트로 destination의
    `TransferFeeAmount.withheld_amount=50`까지 확인
  - [x] `extensions/transfer-fee-config/harvest` (sub 4,
    HarvestWithheldTokensToMint) — devnet-confirmed, permissionless(서명 불요).
    계좌의 `TransferFeeAmount.withheld_amount`(50→0)를 mint의
    `TransferFeeConfig.withheld_amount`(0→50)로 이동하는 것까지 raw 바이트로
    확인
  - [x] `extensions/transfer-fee-config/withdraw-from-mint` (sub 2,
    WithdrawWithheldTokensFromMint) — devnet-confirmed,
    `withdraw_withheld_authority` 서명 필요. mint의 `withheld_amount`(50→0)를
    destination 실제 토큰 잔액(+50)으로 인출하는 것까지 확인
  - [x] `extensions/transfer-fee-config/withdraw-from-accounts` (sub 3,
    WithdrawWithheldTokensFromAccounts) — mint를 거치지 않고 계좌들에서 직접
    authority가 인출. 계정 순서가 특이함(authority가 source 목록보다 먼저:
    mint, destination, authority(+멀티시그), 그 다음 source들 — 다른 곳처럼
    authority를 맨 뒤에 붙이는 패턴이 아님, upstream 확인 후 그대로 구현)

  **`TransferFeeExtension`(opcode 26) 6개 서브인스트럭션 전부 완료 — devnet
  전체 lifecycle 검증 끝.** initialize → set → transfer(자동 수수료 계산) →
  harvest(계좌→mint) → withdraw-from-mint(mint→실제 인출) →
  withdraw-from-accounts, 전부 raw 바이트/RPC parsed 로그로 확인.

  `core/extensions.go`로 확장 관련 코드 전부 분리함 (`core/token.go`는 기본
  Token 인스트럭션만). `ExtensionType` 상수, sub-instruction discriminant,
  `GetAccountDataSize`/`Reallocate`/`CalculateMintExtensionsLen` 빌더,
  `TransferFeeConfig` 관련 전부 여기.

  그다음: 확장별 enable/disable(활성화) — `Reallocate`는 자리만 만들 뿐 확장을
  "존재하게" 만들진 않음, 그건 패밀리마다 다른 서브인스트럭션의 몫. 대략:
  - 단순 toggle 쌍: `memo_transfer`, `cpi_guard` (Enable/Disable)
  - Initialize(+Update), disable 없음: `transfer_fee_config`, `default_account_state`,
    `interest_bearing_config`, `transfer_hook`, `metadata_pointer`, `group_pointer`,
    `group_member_pointer`, `scaled_ui_amount`, `pausable`(Initialize/Pause/Resume) 등
  - 자동 관리, 별도 엔드포인트 불필요: `non_transferable_account`,
    `transfer_hook_account`, `pausable_account` 등
  - **한 번 확장이 계좌/mint에 붙으면 영구히 제거 불가** — 값을 끄거나(disable)
    바꿀 순 있어도 TLV 항목 자체를 지우는 인스트럭션은 프로토콜에 없음
    (Reallocate도 줄이는 방향은 지원 안 함). 확인 완료, 규칙으로 기억할 것.

- **별도 서브시스템 (discriminator/구조부터 다시 조사 필요, 규모 큼)**
  - `spl-token-metadata-interface` — 5개 instruction, discriminator 확인됨
    (SHA256("spl_token_metadata_interface:<name>")의 앞 8바이트, Token-2022가
    직접 구현 — 별도 프로그램 아님). Initialize/UpdateField/RemoveKey/
    UpdateAuthority/Emit
  - `spl-token-group-interface` — 그룹/그룹멤버 실제 데이터. NFT 컬렉션(그룹)과
    개별 NFT(멤버) 관계 표현. discriminator 방식 아직 미조사
    (InitializeGroup, UpdateGroupMaxSize, UpdateGroupAuthority, InitializeMember)
  - Metaplex Token Metadata — 완전히 다른 프로그램, Borsh 직렬화 새로 배워야 함,
    근데 지갑/익스플로러 실질 표준이라 결국 필요
  - Confidential Transfer / Confidential Transfer Fee / Confidential Mint Burn —
    ElGamal 암호화가 들어가는 가장 무거운 서브시스템 (각각 15/6/6개 instruction)

- **작은 후속 작업 (나중에)**
  - `getRecentPrioritizationFees` RPC 래퍼 — `svm/cluster/...`에 읽기 전용으로 추가.
    "얼마 낼지"가 아니라 "요즘 시세가 얼마인지" 알려주는 것 (fee 계산 자체는
    이미 `getFeeForMessage`로 정확히 되고 있어서 급하지 않음)
  - `set-transfer-fee` 응답에 `effective_epoch`(현재 epoch+1)와
    `estimated_effective_at`(추정 시각, `getEpochInfo`+평균 슬롯 시간 기반) 추가

- **더 뒤 (더 무거운 선행 작업 필요)**
  - Address Lookup Table — versioned(v0) transaction 지원이 먼저 필요
  - Stake, Vote, Loader/deployment
