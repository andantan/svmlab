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
  **`Transfer`(opcode 27 sub 7) devnet 완주 — 민트 새로 만들어 처음부터
  (mint→ATA 2개→configure→mint-to→deposit→apply→proof→컨텍스트 계정→
  transfer→수신 apply) 전 과정 확인.** 트랜잭션 `4C4vc24m…`, `err: None`,
  15246 CU, RPC parsed 로그의 세 proof offset이 전부 0(컨텍스트 계정 참조)
  으로 찍힘. 송신 decryptable 10→0, 수신 pending 채워짐(credit counter 1)
  후 수신 `apply-pending-balance`(`new_available_balance=20`) 뒤 decryptable
  20·pending 0 확인. (ElGamal 암호문을 직접 복호화한 건 아니고 AE
  decryptable 값과 pending 0 여부로 확인)
  - **막혔던 원인/해결**: proof 3개(equality 320 + validity 544 + range
    1000)를 inline으로 실으면 메시지 3232바이트로 1232 한도 초과
    (`-32602 too large`). proof를 별도 트랜잭션에서 컨텍스트 계정에 미리
    검증·저장하고 `Transfer`는 계정 주소만 참조하는 방식으로 전환.
  - 기존 inline 빌더는 offset을 1,1,1로 박아뒀는데 실제로는 1,2,3이어야 했음
    (어차피 크기 때문에 못 쓰는 경로라 제거). 컨텍스트 모드는 upstream
    `inner_transfer`/`TransferInstructionData` 원문 확인: offset 0=컨텍스트
    계정, 계좌 `[source, mint, dest, equality ctx, validity ctx, range ctx,
    authority(+멀티시그)]`, 인스트럭션 sysvar는 offset 모드일 때만 포함
  - `transfer` 엔드포인트 요청 바디 **변경**: secret key·ae_key·amount·
    현재 잔액 암호문 필드 제거, `equality_context_state_account` /
    `ciphertext_validity_context_state_account` /
    `range_proof_context_state_account` /
    `new_source_decryptable_available_balance` / `auditor_ciphertext_lo` /
    `auditor_ciphertext_hi` 추가. 서버는 컨텍스트 계정 3개의 존재·owner·space만
    확인. 응답에서 `amount`/`new_source_available_balance` 제거
  - **신규 `POST /svm/tool/prove/confidential-transfer`**: 위 proof 3개 +
    auditor ciphertext lo/hi + 새 decryptable 잔액을 한 번에 생성
    (`core.BuildTransferProofs`). 3개가 같은 랜덤 opening을 공유하므로
    따로 만들면 어긋남 — **응답은 재생성 불가**(다시 부르면 이미 검증한
    컨텍스트 계정과 안 맞음). 소스 잔액이 proof 생성~transfer 사이에
    바뀌면 실패
  - 이번에 겪은 것: (1) auditor secret key를 송신 키로 잘못 넣어
    `zkbridge: proof generation failed` — 서버 버그 아님, 도출한 pubkey로
    확인. 민트에 auditor가 있으면 `auditor_elgamal_pubkey`를 반드시 같은
    값으로 넣어야 함. (2) range proof verify 트랜잭션은 nonce 없이 약
    1205바이트, `durable_nonce_account`를 붙이면 약 1311바이트로 한도 초과 —
    이 트랜잭션만 nonce 없이 보낼 것, context_state_account_owner를
    fee_payer와 같은 주소로 두면 계정 목록 32바이트 절약

  **크레딧 토글 4개(opcode 27 sub 9~12) 완료 — proof·데이터 없음, discriminant
  하나뿐, 계좌 `[account(writable), owner(+멀티시그)]`(mint 계좌 없음).**
  계좌의 `allow_confidential_credits`/`allow_non_confidential_credits`
  플래그(확장 값 안 offset 261/262)를 켜고 끄는 스위치. 라우트는
  `confidential-transfer-account/` 아래 인스트럭션 이름 그대로 평평하게
  `enable-confidential-credits`(9), `disable-confidential-credits`(10),
  `enable-non-confidential-credits`(11), `disable-non-confidential-credits`(12).
  요청 필드는 `account`/`owner`(멀티시그면 `multisig_signers`)/`fee_payer`/
  `program`/`recent_blockhash`/`durable_nonce_account`, 타입은 인스트럭션마다
  따로(복사 후 통합)
  - devnet: `disable-non-confidential-credits` 시그니처로 플래그 1→0
    (기밀 수신은 1 유지, 1196 CU, RPC parsed
    `disableConfidentialTransferNonConfidentialCredits`), 이어
    `disable-confidential-credits`로 기밀 플래그도 0(parsed
    `disableConfidentialTransferConfidentialCredits`). 두 enable은 시그니처를
    직접 보진 않았고 둘 다 0이던 계좌가 최종적으로 1,1로 돌아온 걸 온체인에서
    읽어 확인. 꺼진 상태에서 실제 전송이 거부되는지는 시도 안 함
  - 남은 ConfidentialTransfer 없음 — TransferWithFee(13)/ConfigureAccountWithRegistry(14)는
    아래에서 완료

  **`Withdraw`(opcode 27 sub 6) devnet 완주 — 기밀 available → 공개 잔액.**
  트랜잭션 `2ikz2Je…`, `err: None`, 6221 CU, RPC parsed
  `withdrawConfidentialTransfer`의 두 proof offset이 0(컨텍스트 계정
  참조). 수신 계정에서 5를 꺼내 공개 잔액 40→45, 기밀 decryptable 20→15
  (수신 ae_key로 복호화해 확인). ElGamal 암호문 자체를 복호화한 건 아님
  - upstream `inner_withdraw`/`WithdrawInstructionData` 확인: 데이터
    `amount(u64)+decimals(u8)+new_decryptable_available_balance(36)+
    equality offset(0)+range offset(0)`, 계좌 `[account(w), mint, equality
    ctx, range ctx, authority(+멀티시그)]`(offset 모드일 때만 인스트럭션
    sysvar). `Transfer`와 달리 validity proof가 없음 — 목적지·auditor에게
    새로 암호화해 보내는 값이 없어서. 컨텍스트 계정은 equality(161)+
    range u64(297) 두 개
  - proof 구성은 solana-go `NewWithdrawProofData`를 그대로 이식: 남는 잔액
    암호문 = 현재 available − 평문 amount(`elgamal_sub_amount`), 그 잔액에
    새 Pedersen commitment, equality proof, 64비트 range proof
    (`proof_batched_range_u64`, commitment 1개). amount는 공개라 암호화할
    대상이 없음. 서버가 현재 decryptable을 ae_key로 풀어 잔액 초과를 사전 거절
  - `zkbridge`: `ProveBatchedRangeProofU64`(936바이트) 신규, u128과 내부
    구현 공유(`proveBatchedRange`). `ElGamalSubtractAmount` 신규. wasm
    export 두 개를 처음 써봤는데 온체인 검증기가 그대로 받아들임
  - **신규 `POST /svm/tool/prove/confidential-withdraw`**: equality+range
    proof와 `new_decryptable_available_balance`를 한 번에 생성. 두 proof가
    같은 opening을 공유하므로 **재생성 불가**, 계정 잔액이 proof 생성~withdraw
    사이에 바뀌면 실패
  - **신규 `POST .../confidential-transfer-account/withdraw`**: 요청에
    `account`/`mint`/`owner`/`amount`/`decimals`/두 컨텍스트 계정/
    `new_decryptable_available_balance`. decimals는 민트와 대조, 컨텍스트
    계정 존재·owner·space 사전확인. 서버는 proof를 만들지 않음
  - 이제 기밀 잔액이 나오는 길이 생김 — `EmptyAccount`(available을 전부
    withdraw해 0으로 만든 뒤)로 이어갈 수 있음

  **`EmptyAccount`(opcode 27 sub 4) devnet 완주 — 기밀 available을 0 바이트로
  초기화.** 트랜잭션 `31pnDhA8…`, `err: None`, 1677 CU, RPC parsed
  `emptyConfidentialTransferAccount`(`proofInstructionOffset: 0`, 컨텍스트
  계정 참조). 실행 후 계정 데이터를 읽어 `available_balance`가 전부 0
  바이트, `pending_balance_lo/hi`도 0임을 확인
  - **왜 필요한가**: 확장이 붙은 토큰 계정은 `closable()`(pending lo/hi와
    available이 전부 0 **바이트**)이어야 닫힘. `Withdraw`로 잔액을 다
    꺼내도 available은 "값이 0인 랜덤 암호문"이라 0 바이트가 아님. 이
    인스트럭션이 그걸 증명(`VerifyZeroCiphertext`)받고 `EncryptedBalance::
    zeroed()`로 덮어씀. 갓 configure한 계정은 이미 비어 있어 불필요하고,
    available이 이미 비어 있으면 오히려 실패
  - upstream `process_empty_account` 원문 확인: 컨텍스트의 pubkey가
    계정 `elgamal_pubkey`와, 컨텍스트의 ciphertext가 `available_balance`와
    같아야 함(각각 `ElGamalPubkeyMismatch`/`BalanceMismatch`). 데이터는
    `proof_instruction_offset`(i8) 하나, 계좌 `[account(w), zero ctx(r),
    owner(+멀티시그)]`, 컨텍스트 계정은 zero-ciphertext(129바이트)
  - `zkbridge.ProveZeroCiphertext`(wasm `proof_zero_ciphertext`, 192바이트)
    신규. **신규 `POST /svm/tool/prove/confidential-empty-account`**
    (`elgamal_secret_key`+`available_balance_ciphertext` → proof). 이
    엔드포인트는 ciphertext가 실제로 0인지 확인하지 않음(AE 키 없이는
    못 읽음) — 0이 아니면 verify 단계에서 거절됨. **신규 `POST
    .../confidential-transfer-account/empty-account`**: `account`/`owner`/
    `zero_ciphertext_context_state_account`, 컨텍스트 계정 존재·owner·space
    사전확인
  - 순서(devnet 확인): 남은 기밀 잔액 15를 `Withdraw`로 전부 꺼내 공개
    잔액 60·decryptable 0 → **withdraw 뒤의 새 available**로 proof 생성
    (이전 값으로 만들면 거절됨) → `create/verify zero-ciphertext` →
    `empty-account`. 컨텍스트 계정은 이후 `close`로 회수해 사라진 것 확인
  - **미확인**: 비워진 토큰 계정을 실제로 `close-account`로 닫아보진 않음
    (공개 잔액 60이 남아 있어 먼저 비워야 함). "확장이 붙은 채로 닫히는지"는
    아직 미검증

  **신규 최상위 그룹 `/svm/v2/transaction/zk-elgamal-proof/context-state/`**
  (ZkElgamalProof는 Token-2022와 별개 프로그램이라 compute-budget처럼 자기
  그룹). 1 instruction = 1 endpoint, 요청 바디에 proof_type을 받지 않고
  라우트로 분리:
  - [x] `create/<proof-type>` 12개 — System CreateAccount(owner=ZkElgamalProof,
    space는 라우트마다 고정). 키페어 방식만 지원 (seed 방식은 owner가 주소
    도출에 들어가므로 `CreateAccountWithSeed`를 owner=ZkElgamalProof로 한 번에
    호출하는 별도 엔드포인트가 필요 — 미작성)
  - [x] `verify/<proof-type>` 12개 — Verify* 컨텍스트 스테이트 형태
    (accounts `[context(writable), owner(readonly)]`, 데이터는 inline과
    동일). context 계정 존재·owner·space 확인 후 빌드. `pubkey-validity`만
    `elgamal_pubkey`+`pubkey_proof`를 받아 로컬 사전검증, 나머지 11개는
    `proof_data`(base58) 하나
  - [x] `close` 1개(12개 아님 — 인스트럭션이 proof 타입과 무관하게
    `[context, destination, owner(signer)]` 동일). 기록된 authority(데이터
    앞 32바이트)와 owner 일치 사전확인. devnet-confirmed — equality/validity/
    range 컨텍스트 계정 3개를 닫았고 `getAccountInfo`가 전부 `None`
  - space = 32(authority) + 1(proof_type) + context. 12종 전부 인터페이스
    크레이트 `proof_data/*.rs` 원문으로 확인: pubkey-validity 65,
    ciphertext-commitment-equality 161, batched-grouped-3-handles 385,
    batched-range-u128 297, zero-ciphertext 129, ciphertext-ciphertext-equality
    225, percentage-with-cap 137, batched-range-u64/u256 297(세 range proof가
    `BatchedRangeProofContext` 공유), grouped-2-handles 193,
    batched-grouped-2-handles 289, grouped-3-handles 257
  - ProofData 길이(context+proof): 나머지 8종은 `zk-sdk-pod`의
    `*_PROOF_LEN` 상수로 확인 — zero-ciphertext 192,
    ciphertext-ciphertext-equality 416, percentage-with-cap 360,
    range-u64 936, range-u256 1064, grouped-2 320, batched-grouped-2 416,
    grouped-3 416
  - devnet: create 3종(equality/validity/range)+verify 3종 확인 —
    `proof_type` 3/12/7, context 채워짐, authority=지갑0. `pubkey-validity`
    계정(65바이트)·range 계정(297바이트)도 create까지 확인
  - **한계**: `proof_data`를 만들어주는 tool은 `prove/pubkey-validity`와
    `prove/confidential-transfer`(equality·validity·range 3종)뿐. 나머지 8종은
    `zkbridge`에 Prove 함수가 없어 verify 엔드포인트만 있고 실제로 돌려볼
    방법이 없음(wasm이 해당 export를 갖는지부터 확인 필요). create와 verify를
    같은 트랜잭션에 합쳐주는 도구도 없어서, 인터페이스 문서가 경고한
    "미초기화 계정 선점" 여지가 남음(지금은 두 트랜잭션으로 나눠 보냄)
  - 코드 정리: `zk_elgamal_proof_program.go`→`zk_proof.go`,
    `ae_encryption.go`→`crypto.go` 병합, space/len 상수는 const 블록 하나로


  **ZkElgamalProof/Record 확장 + TransferWithFee + ConfidentialTransferFee 전체 —
  devnet 완주 (수수료 민트 `Gy3ef61p…`, 500bp/최대 10000).**
  - `verify-from-account/<proof-type>` 12개: 데이터가 정확히 5바이트
    `[opcode, u32 offset]`, 첫 계정이 proof 계정(소유 프로그램 무관). 큰 proof는
    고정 CU가 커서(range64 111000/128 200000/256 368000) 바디에 `compute_unit_limit`
    (ComputeBudget SetComputeUnitLimit 선행). `ComputationalBudgetExceeded`로 확인.
    inline `verify/*`엔 아직 없음
  - **Record 그룹** `/svm/v2/transaction/record/{create-account,initialize,write,
    set-authority,close,reallocate}` — u256 range proof(1064B)는 인라인 verify가
    1269B로 1232 초과(nonce 없이도)라 SPL Record(`recr1L3P…`, 헤더 33B) 계정에
    write한 뒤 verify-from-account(`proof_offset=33`). write 한 번 ≤~1015B(기본
    900), `POST /svm/tool/split/record-chunks`가 청크 분할. nonce 붙이면 u128
    이상은 트랜잭션이 커서 blockhash로 보내야 함
  - **`TransferWithFee`(sub 13)** `confidential-transfer-account/transfer-with-fee`
    + `tool/prove/confidential-transfer-with-fee`(민트를 읽어 수수료율/auditor/
    withdraw 키를 채움, proof 5종 한 번에: equality·transfer-amount validity·
    percentage-with-cap·fee validity·u256 range). 수수료 민트는 일반 Transfer 거부.
    수수료 파라미터는 현재 epoch 값이어야 함. 1000 전송 → 수수료 50, 44718 CU
  - 수수료 민트에서 `configure-account`는 ConfidentialTransferFeeAmount도 함께
    초기화 → 계정에 182+299+68=549B 필요, `reallocate`에 bool
    `include_confidential_transfer_fee_amount` 추가(두 타입은 한 Reallocate에)
  - **opcode 37 ConfidentialTransferFee 6개 전부 완료**
    (`confidential-transfer-fee-config/…`): `initialize`(0), `withdraw-withheld-
    tokens-from-mint`(1), `withdraw-withheld-tokens-from-accounts`(2),
    `harvest-withheld-tokens-to-mint`(3, 무서명, 소스 계정 여러 개, 1232 검사),
    `enable-harvest-to-mint`(4)/`disable-harvest-to-mint`(5)
  - 수수료 인출은 `ciphertext-ciphertext-equality` proof(416B, context 225B) 필요:
    `tool/prove/confidential-withdraw-withheld-from-mint`·`…-from-accounts`가
    withheld ciphertext(계정들은 합산 — wasm에 add가 없어 `0 - b` 후 sub로 구현)를
    출금 authority ElGamal 비밀키로 복호화(`elgamal_decrypt_u32`)→목적지 키로
    재암호화→proof + 목적지 new_decryptable 반환. 32비트 초과 금액은 불가
  - 온체인 검증: harvest 후 민트 withheld 100 → from-mint로 송신 계정 8000→8100,
    민트 withheld 0. 이어 1000 전송으로 수신 계정 withheld 50 → from-accounts로
    송신 계정 7100→7150, 수신 withheld 0
  - 목적지가 source와 같은 계정이면 borrow 충돌 가능성(미시도) — 다른 계정 사용
  - 남은 것: inline verify의 `compute_unit_limit`, 나머지 proof 종류의 prove
    tool. 이번 실행의 context 7개/record 1개는 close 완료(`getAccountInfo` None).
    authority 미기록으로 회수 불가한 계정(`FvVMM51V…`, `6QEFYcGY…`, `FGEDoT6w…`
    — verify 안 한 것)은 그대로. SIMD-0296(4096B tx)/0385(v1 포맷)는 조사만,
    활성화 여부 미확인, 보류

  **`ConfigureAccountWithRegistry`(sub 14) + ElGamal registry 그룹 — devnet 완주.
  ConfidentialTransfer 15개 전부 완료.**
  - registry 프로그램 `regVYJW7tcT8zipN5YiBvHsvR5jXW1uLFxaHSbugABg`(BPF upgradeable,
    devnet 업그레이드 권한 `7VaWK6qq…`, **메인넷엔 미배포**). 지갑당 PDA
    `["elgamal-registry", wallet]` 하나, 64B = owner(32)+elgamal_pubkey(32).
    소스: `confidential/elgamal-registry{,-interface}`
  - **신규 최상위 그룹 `/svm/v2/transaction/elgamal-registry/{create,update}`** —
    pubkey-validity context 계정(65B)을 받음. create는 wallet 서명, PDA는 서버가 도출
  - **프로그램은 PDA에 allocate+assign만 하고 lamports를 채우지 않음** —
    잔액이 rent-exempt 미만이면 `AccountNotRentExempt`. 처음엔 이걸 몰라 devnet
    에서 실패, `create`에 `rent_payer`를 추가해 부족분 System Transfer를 같은
    트랜잭션 앞에 넣음(이미 미리 채운 주소면 그 잔액을 반영, 다른 용도 계정이면 거절)
  - **close/delete 명령 없음**(`RegistryInstruction`은 0/1뿐, 소유 프로그램만
    lamports를 뺄 수 있음) → registry rent(~0.0013 SOL)는 회수 불가. 테스트는 새
    지갑에 만들 것(지갑당 하나라 같은 지갑으로 재생성 불가)
  - `confidential-transfer-account/configure-account-with-registry` (데이터 없음,
    `[27,14]`): accounts `[token(w), mint, registry, (rent_payer(w,signer), system)]`.
    **owner 서명 불필요**(registry owner == 토큰 계정 owner만 확인) → 남이 대신
    설정 가능. `rent_payer`를 주면 프로그램이 직접 realloc(수수료 민트면
    ConfidentialTransferFeeAmount 자리까지) → 별도 `reallocate` 불필요.
    (필드명은 처음 `payer`였다가 다른 API와 맞춰 `rent_payer`로 통일)
  - 초기값: decryptable all-zero, 최대 pending counter 65536, allow_* 1/1,
    approved는 민트 auto-approve를 따름(이 민트는 0 → approve-account 필요)
  - devnet 검증(새 지갑): registry create → ATA(182B) → configure-with-registry 한
    번에 **549B**(CT 295 + fee amount 64 확장 모두 붙음), 계정 elgamal_pubkey ==
    registry 값. 이어 approve → mint-to 100 → deposit 100 → apply-pending-balance:
    AE 복호화 100, registry 등록 ElGamal 키로 available ciphertext 복호화도 100,
    pending 0. **all-zero decryptable이 첫 apply에서 정상화됨을 확인**
  - `update` 전송 devnet 확인: 새 ElGamal 키의 pubkey-validity context로 registry의
    키가 바뀌고 owner는 유지. **이미 configure된 계정의 키는 예전 그대로** — update는
    이후 configure에만 영향
  - 서명 기반 AE 키 도출 확인: `derive/ae-key-seed-message` → 계정 owner 키로 메시지
    서명(서버 `/svm/sign`은 설정에 없는 키로 메시지를 못 서명해 로컬에서 ed25519로
    서명) → `derive/ae-key`로 받은 키로 mint-to/deposit/apply(총 150) → AE 복호화
    150, ElGamal 복호화도 150

  **ConfidentialMintBurn(opcode 42) 6개 전부 — devnet 완주 (민트 `CyFziHgy…`).**
  확장 상태 196B = confidential_supply(64)+decryptable_supply(36)+
  supply_elgamal_pubkey(32)+pending_burn(64), TLV 타입 24. 확장 붙은 민트는
  `create-mint`(고정 82B)가 아니라 `mint/data-size`(CT mint+MintBurn=435B) →
  `system/create-account`(0B) → `allocate` → `assign`(Token-2022) → 확장별 initialize →
  `initialize-mint2` 순서(단계 사이 선점 위험은 기존과 동일). 새 proof 종류 없음 —
  transfer의 prover(equality·validity-3·range u128)를 재사용
  - `confidential-mint-burn/initialize`(0): `supply_elgamal_pubkey`+`supply_ae_key`
    (서버가 0을 AE 암호화해 decryptable_supply로), all-zero 키는 "없음"이라 거절
  - `mint`(3) + `tool/prove/confidential-mint`: 3-handle 순서 [destination, supply,
    auditor]. 새 공급량 ciphertext = 현재 공급량 + supply handle의 lo/hi 합(프로그램이
    같은 식으로 계산해 바이트 비교). 목적지 pending과 공급량이 동시에 늘어남.
    authority = **민트 authority**. 1000 발행 → 목적지 pending 1000, 공급량 1000
  - `burn`(4) + `tool/prove/confidential-burn`: [source, supply, auditor] —
    `BuildTransferProofs`에 목적지 자리를 supply 키로 넣은 것. authority = **토큰
    계정 owner**(민트 authority 아님). 400 소각 → available 600, 민트 pending_burn 400,
    공급량은 그대로 1000
  - `apply-pending-burn`(5): 공급량 -= pending_burn, pending_burn = 0(→ 600).
    decryptable_supply는 건드리지 않음
  - `update-decryptable-supply`(2): `supply_ae_key`+`new_supply`를 서버가 AE 암호화.
    프로그램이 공급량과 대조 못 하므로 호출자가 실제 값을 넣어야 함(apply 직후
    1000 → 600으로 맞춤)
  - `rotate-supply-elgamal-pubkey`(1) + `tool/prove/confidential-rotate-supply-
    elgamal-pubkey`: ciphertext-ciphertext-equality(수수료 인출과 같은 종류).
    pending_burn 0 필요, 공급량 32비트 이하(복호화 한계). 회전 후 새 키로 복호화 600,
    옛 키로는 `decryption failed`, 새 키로 만든 mint 100이 통과(공급량 700)
  - 미확인/미착수: **PermissionedBurn의 ConfidentialBurn 변형**(별개 확장, 승인자 계정이
    하나 더 들어가고 PermissionedBurn 민트는 일반 Burn을 거절 — 코드에 타입/명령 번호만
    있고 빌더 없음), 멀티시그 authority 경로(모든 빌더가 받지만 devnet 미실행), 확장이
    붙은 민트/계정의 close, 동결/CpiGuard/일시정지 등 조합

  **2026-09-26 남은 확장 전수 재조사** — 업스트림 `ExtensionType` enum(실제 확장 16개
  남음) + 확장별 명령 enum + `AuthorityType` 0~17과 우리 라우트를 대조한 결과:
  - 완료: transfer-fee(config/amount), mint-close-authority, confidential-transfer 계열
    3개(27/37/42), immutable-owner, 그리고 아래 이번에 만든 것들
  - **남은 것(명령)**: default-account-state 2, interest-bearing 2, scaled-ui-amount 2,
    pausable 3, transfer-hook 2, metadata-pointer 2, group-pointer 2,
    group-member-pointer 2, permissioned-burn 4(Initialize/Burn/BurnChecked/
    ConfidentialBurn), token-metadata 5(Initialize/UpdateField/RemoveKey/UpdateAuthority/
    Emit), token-group 4(InitializeGroup/UpdateGroupMaxSize/UpdateGroupAuthority/
    InitializeMember)
  - TokenMetadata/TokenGroup/TokenGroupMember도 **확장이 맞다**(타입 19/21/23) —
    "별도 서브시스템"으로 분류한 건 해시 discriminator·가변 길이라 만드는 방식이 달라서일
    뿐. **Token-2022 전용**: 기존 SPL Token의 이름·이미지는 Metaplex Token Metadata
    (PDA `["metadata", metaplex, mint]`, 소유 `metaqbxx…`)가 담당 — EURC 민트(82B,
    Tokenkeg)로 온체인 확인(이름/심볼/uri 모두 Metaplex 계정 679B에 있음)
  - **SetAuthority의 확장 권한 타입 13종 미구현**: 4 TransferFeeConfig, 5 WithheldWithdraw,
    7 InterestRate, 8 PermanentDelegate, 9 ConfidentialTransferMint, 10 TransferHookProgramId,
    11 ConfidentialTransferFeeConfig, 12~17(포인터 3종/ScaledUiAmount/Pause/PermissionedBurn).
    `core/token.go`의 "4·5는 InitializeTransferFeeConfig가 다루므로 SetAuthority로 안 다룬다"는
    주석은 **틀렸음**(초기화 때 정한 authority를 나중에 바꾸는 유일한 길이 SetAuthority).
    각 확장을 만들 때 그 확장의 타입을 함께 만들 것
  - reallocate 27개 계획은 mint 전용 타입이 항상 `ExtensionTypeMismatch`라 가치가 낮음 —
    계정 쪽 타입만 남기는 방향으로 재논의 필요

  **단독 명령 3개 + memo-transfer/cpi-guard — devnet 확인.**
  - 공용 생성기 `gen_init.py`(스크래치패드): mint 전용 Initialize 엔드포인트(types+handler)를
    `InitializeMintCloseAuthority` 모양으로 찍어냄. 이후 확장에서 재사용
  - `extensions/non-transferable/initialize`(opcode 32, 데이터 없음),
    `extensions/permanent-delegate/initialize`(35, delegate 32B 필수),
    `token/create-native-mint`(31, Token-2022 전용, `rent_payer`). 크기 206B(NT 4B+PD 36B)
    - 확장 붙은 ATA에 ImmutableOwner(7)/NonTransferableAccount(13)이 **자동**으로 붙음
    - NonTransferable 전송은 프로그램이 `Custom(37)` "Transfer is disabled for this mint"
    - **영구 위임자가 승인 없이 남의 계정에서 소각** 성공(10→7) — 단 우리 `token/burn`은
      "owner 또는 승인된 delegate만" 사전검사로 거절 → 직접 만든 트랜잭션으로 확인
    - create-native-mint: `9pan9bMn…`이 이미 있어 성공 검증 불가(사전검사 메시지까지만)
  - 필드명 정리: `fee_payer`(수수료) / `rent_payer`(새 계정·리사이즈 보증금) /
    `funding_payer`(System Transfer 출금 전용). create-native-mint을 처음
    `funding_account`로 지어 `rent_payer`로 정정
  - `extensions/memo-transfer/{reallocate,enable,disable}`(opcode 30, sub 0/1),
    `extensions/cpi-guard/{reallocate,enable,disable}`(34, sub 0/1): 계정 쪽 확장(타입 8/11,
    각 1B). enable/disable 둘 다 확장이 없으면 **스스로 붙임**(자리는 reallocate가 만듦)
    - memo: 170→175B, 메모 없는 전송 `Custom(36)` "No memo in previous instruction required",
      Memo 명령을 앞에 붙이면 통과(로그 `"hello memo"`), disable 후 메모 없이 통과
    - cpi-guard: 값 00/01 토글 확인. **CPI 안에서의 실제 차단은 미확인**(CPI 호출
      프로그램을 만들 수 없음)
  - **기존 엔드포인트 보완 패스(확장 다 만든 뒤 일괄)**: ① transfer/burn 등 사전검사 14곳이
    영구 위임자를 authority로 못 받음, ② NonTransferable 민트 전송을 미리 거절, ③ memo 필수
    계정으로의 전송에 선택 필드 `memo`로 Memo 명령을 앞에 붙이는 기능(우리 API엔 Memo
    명령을 붙일 방법이 없음), ④ 이후 transfer-hook 추가 계정/pausable 정지 등 조건 추가


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
  - Confidential Transfer(15개)/Transfer Fee(6개)/Mint Burn(6개) 전부 완료 — 남은 건
    PermissionedBurn의 ConfidentialBurn, 멀티시그·close 검증 정도

- **작은 후속 작업 (나중에)**
  - `getRecentPrioritizationFees` RPC 래퍼 — `svm/cluster/...`에 읽기 전용으로 추가.
    "얼마 낼지"가 아니라 "요즘 시세가 얼마인지" 알려주는 것 (fee 계산 자체는
    이미 `getFeeForMessage`로 정확히 되고 있어서 급하지 않음)
  - `set-transfer-fee` 응답에 `effective_epoch`(현재 epoch+1)와
    `estimated_effective_at`(추정 시각, `getEpochInfo`+평균 슬롯 시간 기반) 추가

- **더 뒤 (더 무거운 선행 작업 필요)**
  - Address Lookup Table — versioned(v0) transaction 지원이 먼저 필요
  - Stake, Vote, Loader/deployment
