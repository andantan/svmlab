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
  - [x] `mint-close-authority` — devnet-confirmed. `transfer-fee-config`와
    동일하게 mint 전용 타입이라 계좌(`DBWKXnofLJnH9uTiLdfMmQd3iEde8VuL4sd6987Xn9ET`)에
    걸었더니 예상대로 `Custom(20)`(`ExtensionTypeMismatch`)로 실패, 우리
    핸들러의 내부 `GetAccountDataSize` 사전검증 단계에서 걸려서 실제
    `Reallocate` 트랜잭션이 만들어지기도 전에 차단됨
  - [x] `confidential-transfer-mint` — devnet-confirmed. mint 전용 타입이라
    계좌(`DBWKXnofLJnH9uTiLdfMmQd3iEde8VuL4sd6987Xn9ET`)에 걸었더니 예상대로
    `Custom(20)`(`ExtensionTypeMismatch`)로 실패

  **`ConfidentialTransferMint`(ExtensionType 4, opcode 27 서브패밀리) —
  `InitializeMint`(sub 0), `UpdateMint`(sub 1) devnet-confirmed.** 15개
  서브인스트럭션 중 ElGamal 수학이 필요 없는 건 이 둘뿐(처음엔
  InitializeMint 하나뿐이라고 잘못 판단했다가, `update_mint` 소스 재확인 후
  정정).

  **"미루지 않고 끝까지 간다"는 방침으로 ZK proof 필요한 서브인스트럭션도
  착수 — `ConfigureAccount`(sub 2, 계좌 쪽 `ConfidentialTransferAccount`
  확장) 코드 작성 완료, 빌드/유닛테스트 통과, devnet 테스트는 아직.**
  필요했던 암호 인프라 전부 신규 구축:
  - **ElGamal 키 생성 버그 발견+수정**: Solana의 "twisted ElGamal"은
    `공개키 = 비밀키 × G`(표준)가 아니라 `공개키 = 비밀키⁻¹ × H`(H는 G와
    다른 별도 생성원 = `SHA3-512(G)`를 hash-to-group한 값) — `pedersen.rs`/
    `elgamal.rs` 소스로 확인, `core.GenerateElGamalKey` 수정.
    `core.DeriveElGamalPublicKey(secretKey)`도 추가(secret만으로 public 유도)
  - **`core/zk_proof.go`**: `PubkeyValidityProof`(Schnorr sigma-protocol)
    직접 Go로 구현 — `github.com/gtank/merlin`(Rust `merlin` crate와 프로토콜
    호환되는 Go 포트) 사용. transcript 라벨까지 Rust 소스(`transcript.rs`,
    `pubkey_validity.rs`)로 바이트 단위 확인:
    `Transcript::new(b"pubkey-validity-instruction")` →
    `append_message(b"pubkey", pubkey)` → `append_message(b"dom-sep",
    b"pubkey-proof")` → `Y=y·H` 커밋 → `append_point(b"Y", Y)` →
    `challenge_scalar(b"c")`(64바이트 뽑아 mod l 축소) → `z=c·s⁻¹+y`.
    `ProvePubkeyValidity`/`VerifyPubkeyValidity` 둘 다 구현(로컬 자체 검증용)
  - **`core/ae_encryption.go`**: `decryptable_zero_balance`용 AES-128-GCM-SIV
    (RFC 8452) — `github.com/secure-io/siv-go` 사용(2018년 이후 미유지보수지만
    RFC 8452 공식 테스트 벡터로 직접 고정 검증 완료, 알고리즘 자체는 고정
    표준이라 라이브러리 낙후는 무관). `AeKey` 유도도 **제대로**(랜덤 아님)
    구현: upstream `AeKey::new_from_signer`와 동일하게
    `SHA3-512(SHA3-512(sign(b"AeKey"||token_account)))[:16]` —
    `solana-foundation/Confidential-Balances-Sample`에서 `public_seed`가
    토큰 계좌 자신의 주소라는 관례 확인. 서버가 서명키를 안 쥐고 있으므로
    2단계로 분리: `/svm/tool/derive/ae-key-seed-message`(서명할 메시지 반환)
    → 기존 `/svm/sign` → `/svm/tool/derive/ae-key`(서명→키)
  - **`core/zk_elgamal_proof_program.go`**: `zk_elgamal_proof` 프로그램
    (`ZkE1Gama1Proof11111111111111111111111111111`) 신규 — `agave`가 이
    프로그램의 interface crate(`solana-program/zk-elgamal-proof`)를
    가져다 쓰는 구조까지 확인해서 원본 확실히 함. 13개 opcode 전부 상수로
    선언(공식 Rust 소스로 재검증, `VerifyPubkeyValidity=4`), inline
    verify(증명을 계좌 없이 인스트럭션 데이터에 직접 실음, accounts 없음)만
    구현
  - **`core.(*token).ConfigureAccount`**: opcode 27 sub 2. 데이터
    `decryptable_zero_balance`(36)+`maximum_pending_balance_credit_counter`(8)+
    `proof_instruction_offset`(1). 계좌
    `[account(writable), mint, sysvar::instructions]`+authority — 전부
    `solana-foundation/solana-go`(공식 Go SDK, Rust 재구현 없이 WASM 브릿지
    쓰는 걸 확인한 그 라이브러리)의 `ConfidentialTransferConfigureAccount.go`
    로 계좌 순서/데이터 레이아웃 교차검증
  - **`/svm/v2/transaction/token/extensions/confidential-transfer-account/
    configure-account`**: `ConfigureAccount`+`VerifyPubkeyValidity` 두
    인스트럭션 한 트랜잭션에 자동 조립(offset=1). 요청 시 `pubkey_proof`를
    로컬에서 먼저 `core.VerifyPubkeyValidity`로 검증(온체인 검증기가 할 걸
    미리 해봄) 후 안 맞으면 트랜잭션 만들기 전에 400 반환 — 괜히 수수료
    날리는 것 방지
  - **`extensions/confidential-transfer-account/reallocate`** devnet-confirmed
    (계좌 쪽 진짜 확장이라 성공, 위 `reallocate/*` 목록에도 기록). ATA
    `F6GZ7t5Qj522mYAinGExV3WKEgJ7ySThva8J7cFZnLXn`(mint
    `8XiV2ZjDnYvRUc7icjiATmmuojpeKJWUidjZcnpGL65y`)로 170→469바이트
    (165+1+4+0(ImmutableOwner)+4+295(ConfidentialTransferAccount)) 정확히
    일치 확인. raw 바이트로 `Reallocate`는 공간만 늘리고 TLV는 안 쓴다는 것도
    재확인(늘어난 영역이 `Uninitialized`(0)로 비어있음) — 다음 단계
    `ConfigureAccount`가 실제로 채움. 참고: 첫 시도에서 우연히 일시적인
    `Custom(20)` 실패가 있었는데, 같은 조합을 `get-account-data-size`로
    단독/조합 재확인 후 재시도하니 정상 성공 — 코드 문제 아니었음(원인
    특정은 안 됐지만 재현 안 됨)
  - **테스트 예외**: `no-tests-by-choice` 원칙은 나머지 코드베이스 전체에
    적용되는 것이고, 이 암호 코드(`core/zk_proof.go`,
    `core/ae_encryption.go`, `core/crypto.go`의 ElGamal 부분)만 사용자가
    명시적으로 테스트 작성 요청해서 예외. RFC 8452 공식 벡터, ristretto255
    G 상수 고정, 증명 라운드트립+변조 거부 등 11개 테스트 전부 통과
  - **버그 발견+수정 (devnet 실전 테스트로만 잡힘)**: `configure-account`
    devnet 테스트에서 `ConfigureAccount` 자체는 성공했는데 그 다음
    `VerifyPubkeyValidity`가 `SigmaProof(PubkeyValidity, AlgebraicRelation)`로
    실패. 원인: merlin transcript 최상위 래핑을 빼먹음 —
    `Transcript::new_zk_elgamal_transcript(b"pubkey-validity-instruction")`가
    실제로는 `Transcript::new(TRANSCRIPT_DOMAIN=b"solana-zk-elgamal-proof-
    program-v1")` 다음에 **별도로** `dom-sep→"pubkey-validity-instruction"`을
    또 붙이는 이중 래핑인데, 나는 `"pubkey-validity-instruction"`을 최상위
    `Transcript::new()` 인자로 바로 써버림 (`TRANSCRIPT_DOMAIN`의 존재
    자체를 몰랐음). `core.pubkeyValidityTranscript` 수정, `zk_lib.rs`
    직접 raw로 받아서 `TRANSCRIPT_DOMAIN` 상수 확인.
    **로컬 라운드트립 테스트로는 이 버그를 못 잡는다는 것도 확인** —
    prove/verify 둘 다 똑같이 틀린 transcript를 쓰니 서로는 일치해서
    통과했었음, 실제 온체인 검증기와 대조해야만 드러나는 종류의 버그.
    수정 후 재빌드+로컬 테스트 통과 → **재시도해서 devnet-confirmed까지
    완료**: `ConfigureAccount`+`VerifyPubkeyValidity` 둘 다 success, raw
    바이트로 TLV(type=5, len=295) 안의 `elgamal_pubkey`(payload[1:33] —
    `approved` bool 1바이트가 맨 앞에 있어서 오프바이원 주의)가 요청 값과
    정확히 일치하는 것까지 확인. ATA
    `F6GZ7t5Qj522mYAinGExV3WKEgJ7ySThva8J7cFZnLXn` 최종 469바이트, mint
    `8XiV2ZjDnYvRUc7icjiATmmuojpeKJWUidjZcnpGL65y`

  **`ConfigureAccount`(opcode 27 sub 2, `ConfidentialTransferAccount`
  확장 부착) 완전히 끝. ZK proof 필요한 서브인스트럭션 중 첫 완주 사례 —
  Schnorr proof부터 AES-GCM-SIV, 별도 zk_elgamal_proof 프로그램 연동까지
  전부 처음부터 구축, 실전 devnet 테스트로 transcript 버그 하나 잡고 수정,
  최종 성공까지 확인.**

  - [x] `extensions/confidential-transfer-account/approve-account`
    (opcode 27 sub 3, `ApproveAccount`) — devnet-confirmed. proof 불필요,
    데이터도 discriminant뿐. mint의 `auto_approve_new_accounts=false`일 때
    `authority`가 계좌의 `approved` 플래그를 켜주는 역할. RPC parsed 로그
    `type: "approveConfidentialTransferAccount"` 확인.
  - [x] `extensions/confidential-transfer-account/deposit` (opcode 27
    sub 5, `Deposit`) — devnet-confirmed. 공개 잔액 → confidential pending
    balance로 옮기는 진입점, proof 불필요(아직 공개 상태인 금액을 옮기는
    거라 증명할 게 없음 — proof는 `Transfer`처럼 이미 암호화된 값을 다룰
    때부터 필요). 데이터 `amount`(u64)+`decimals`(u8), 계좌
    `[account(writable), mint, authority(+멀티시그)]`. `mint-to`로 공개
    잔액 10개 찍은 뒤 그중 10개를 deposit, RPC parsed 로그
    `type: "depositConfidentialTransfer"`, `amount: 10` 확인. 같은 계좌
    안에서 일어나는 동작이라 계좌 1개로 테스트 가능 — `Transfer`부터는
    계좌 2개(source+destination 둘 다 confidential 설정 완료) 필요
  - [x] `extensions/confidential-transfer-account/apply-pending-balance`
    (opcode 27 sub 8, `ApplyPendingBalance`) — devnet-confirmed. proof
    불필요, mint 계좌도 안 씀(`[account, authority]`뿐). 데이터
    `expected_pending_balance_credit_counter`(u64) +
    `new_decryptable_available_balance`(36바이트 AE 암호문). 이
    엔드포인트는 confidential 잔액을 직접 복호화하지 않으므로
    `new_available_balance`(apply 후 총 available 잔액)를 호출자가 직접
    계산해서 넘겨야 함 — `ae_key`로 서버가 AE 암호화만 해줌. RPC parsed
    로그 `type: "applyPendingConfidentialTransferBalance"`,
    `expectedPendingBalanceCreditCounter: 1` 확인. `Deposit`으로 넣은 10개가
    pending→available로 정상 이동(지갑 UI에서도 계좌 extensions 상태 변화
    확인됨)
  ApplyPendingBalance 등)는 여전히 진행 중 — 각각 필요한 proof 종류가 다름
  (range proof, ciphertext equality proof 등), 하나씩 순서대로 계속.
  - `core.UpdateConfidentialTransferMint` (opcode 27 sub 1): `UpdateMintData`엔
    `authority` 필드가 아예 없음(InitializeMint와 다름) — authority는 데이터가
    아니라 계좌 서명으로 증명, 그래서 이 인스트럭션으로 authority 자체는
    못 바꿈. `auto_approve_new_accounts`+`auditor_elgamal_pubkey` 두 필드만
    전부 덮어씀. **`initialize-mint2` 이후에만 동작** — `SetTransferFee`와
    같은 패턴. `process_update_mint`가 쓰는 `PodStateWithExtensionsMut::
    <PodMint>::unpack`이 `AccountType`이 정확히 `Mint`(1)여야만 통과하고
    `Uninitialized`(0)면 `InvalidAccountData`로 실패하는 것까지 소스로 확인.
    devnet 테스트: `auto_approve_new_accounts` true→false,
    `auditor_elgamal_pubkey` 교체 — RPC parsed 로그(`autoApproveNewAccounts:
    false`, `auditorElGamalPubkey` 새 값)와 지갑 UI("New Account Approval
    Policy: manual")까지 교차 확인
  - `core.InitializeConfidentialTransferMint`: `authority`/`auditor_elgamal_pubkey`
    둘 다 `TransferFeeConfig`의 1바이트 태그 COption과 다르게 **고정 32바이트
    `MaybeNull`**(전부 0이면 None) 인코딩 — `appendMaybeNullAddress`(Address용),
    `appendMaybeNull32`(ElGamal 키처럼 Address 아닌 32바이트 값용) 신규 헬퍼로
    구현, `InitializeMintData` struct(`authority: MaybeNull<Address>`,
    `auto_approve_new_accounts: Bool`, `auditor_elgamal_pubkey:
    MaybeNull<PodElGamalPubkey>`)로 upstream 확인. 데이터 길이 32+1+32=65,
    `extensionTypeDataLen`에 이미 있던 값과 일치 확인
  - `token/extensions/mint/data-size`로 235바이트(165+1+4+65) 계산 →
    create-account→allocate→assign→initialize 흐름 devnet 성공, raw 바이트로
    TLV(type=4, len=65) 및 `authority`/`auto_approve_new_accounts` 값까지
    정확히 확인. None 케이스(`auditor_elgamal_pubkey` 빈 값 → 전부 0)와
    Some 케이스(`/svm/tool/generate/elgamal-keypair`로 만든 실제 ElGamal
    공개키 지정 → raw 바이트가 base58 디코드값과 정확히 일치) 둘 다 devnet에서
    확인 완료
  - **신규 `/svm/tool/generate/elgamal-keypair`** 추가 — `auditor_elgamal_pubkey`
    같은 ristretto255 ElGamal 키를 생성해주는 유틸. `github.com/gtank/ristretto255`
    라이브러리 신규 도입(`core.GenerateElGamalKey`: 64바이트 랜덤 → 스칼라로
    축소 → `공개키 = 스칼라⁻¹ × H`, 이후 세션에서 정확한 공식으로 수정됨 —
    자세한 건 위쪽 "ElGamal 키 생성 버그 발견+수정" 항목 참고). 기존
    `/svm/tool/generate/keypair`는 `/svm/tool/generate/ed25519-keypair`로
    라우트 이름 변경(ElGamal 것과 구분하기 위해)
  - `reallocate/confidential-transfer-mint`도 devnet-confirmed (위에서 이미
    기록, mint 전용이라 계좌에 걸면 실패하는 게 정상)
  - [ ] 나머지 23개, `ExtensionType` enum 선언 순서대로 하나씩
    (다음은 `ConfidentialTransferAccount`, 스크립트로 일괄 생성 안 함, 각각
    개별 작업)
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

  `MintCloseAuthority`(ExtensionType 3, mint 전용, 데이터 32바이트) — 진행 상황:
  - [x] `extensions/mint-close-authority/initialize` (opcode 22,
    `InitializeMintCloseAuthority` — TransferFeeExtension처럼 서브패밀리가
    아니라 독립 top-level opcode라 두 번째 discriminant 바이트 없음) —
    devnet-confirmed. `close_authority`는 `COption<Pubkey>` 타입이지만
    `appendPubkeyOption`(1바이트 태그)으로 인코딩, `InitializeTransferFeeConfig`
    때 확인한 것과 동일한 `pack_pubkey_option` 인코딩. 202바이트
    (165+1+헤더4+데이터32) mint 만들어서 raw 바이트로 TLV(type=3, len=32)와
    데이터 값(지정한 close_authority 키)까지 정확히 일치 확인
  - [x] `extensions/mint-close-authority/set-authority/replace`,
    `/set-authority/clear` — devnet-confirmed. 새 서브인스트럭션이 아니라
    **기존 `SetAuthority`(opcode 6)를 재사용**, `TokenAuthorityCloseMint = 6`
    상수 추가(0~3과 non-contiguous, upstream `AuthorityType::CloseMint => 6`
    확인) + 기존 `SetAuthority` builder 범위 체크에
    `&& != TokenAuthorityCloseMint` 예외 추가. `close_authority`는
    `TransferFeeConfig`의 두 authority와 동일한 `MaybeNull<Address>`(전부
    0이면 None) 인코딩 — 새 `core.DecodeMintCloseAuthority` 헬퍼로 디코드해서
    현재 authority 일치 검증 후 SetAuthority 호출. RPC parsed 로그에서
    `authorityType: "closeMint"` 확인, `replace`(지갑0→지갑1) 후
    `clear`(newAuthority: None)까지 확인, raw 바이트로 최종
    TLV(type=3, len=32)가 전부 0으로 클리어된 것까지 확인. **clear는
    영구적** — None이 된 authority로는 아무도 서명 못 해서 다시 set할 방법이
    없음, mint_authority 클리어와 동일한 원리로 확인 완료
  - [x] `extensions/mint-close-authority/close` — **정정**: 처음에 "기존
    `close-account` 엔드포인트 그대로 재사용 가능"이라고 했던 건 틀렸음.
    온체인 `CloseAccount`(opcode 9) 인스트럭션 자체는 mint든 토큰 계좌든
    동일하게 재사용 가능한 게 맞지만(`process_close_account`가 TokenAccount로
    언팩 시도 후 실패하면 Mint로 폴백), 우리 쪽 `close-account` **핸들러**는
    클라이언트 검증 단계에서 `core.DecodeTokenAccount`로 파싱하고
    `TokenAccount.CloseAuthority` 필드를 체크하는데, mint의 raw 바이트는
    완전히 다른 레이아웃(82바이트 base + TLV)이라 이 필드 자체가 존재하지
    않음 — 그대로 썼으면 파싱 에러나 오검증이 났을 것. 그래서 별도
    엔드포인트로 새로 만듦: `core.DecodeMint`로 `supply==0` 확인(온체인
    `MintHasSupply` 체크 클라이언트에서 선제 검증) + `core.DecodeMintCloseAuthority`로
    close_authority 검증, 빌더는 기존 `core.CloseAccount` 그대로 재사용.
    devnet-confirmed — supply 0인 mint에 대해 `closeAccount` 성공(RPC parsed
    로그 확인), 이후 그 mint 주소로 `getAccountInfo` 조회하면 `value: null`
    (계좌 완전히 삭제 + rent 회수)까지 확인

  **`MintCloseAuthority`(ExtensionType 3) 전체 lifecycle 완료 —
  initialize → replace/clear → close, 전부 devnet-confirmed.**

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
