// @title           SVMlab API
// @version         1.0
// @description     Solana transaction API
// @host            localhost:33153
// @BasePath        /
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/api/handler/account"
	"github.com/andantan/svmlab/api/handler/misc"
	"github.com/andantan/svmlab/api/handler/token"
	v1 "github.com/andantan/svmlab/api/handler/v1"
	v2 "github.com/andantan/svmlab/api/handler/v2"
	_ "github.com/andantan/svmlab/docs"
	"github.com/andantan/svmlab/internal/config"
	"github.com/andantan/svmlab/internal/rpc"
	"github.com/andantan/svmlab/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := util.FindProjectRoot()
	if err != nil {
		return err
	}

	cfg, err := config.Load(filepath.Join(root, "config.yaml"))
	if err != nil {
		return err
	}

	cluster := rpc.NewCluster(cfg.Chains)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/svm/rpc", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		rpcHandler := misc.NewRPCHandler()
		r.Post("/", rpcHandler.Raw)
		r.Post("/batch", rpcHandler.Batch)
	})

	r.Route("/svm/token", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		tokenHandler := token.NewTokenHandler()
		r.Post("/mint", tokenHandler.Mint)
		r.Post("/account", tokenHandler.Account)
		r.Post("/ata/derive", tokenHandler.ATADerive)
		r.Post("/ata/validate", tokenHandler.ATAValidate)
		r.Post("/amount-to-ui", tokenHandler.AmountToUi)
		r.Post("/ui-to-amount", tokenHandler.UiToAmount)
		r.Route("/extensions", func(r chi.Router) {
			r.Post("/get-account-data-size", tokenHandler.GetAccountDataSize)
			r.Post("/mint/data-size", tokenHandler.MintDataSize)
		})
	})

	r.Route("/svm/cluster", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		clusterHandler := misc.NewClusterHandler()
		r.Post("/blockhash", clusterHandler.BlockHash)
		r.Post("/genesis-hash", clusterHandler.GenesisHash)
		r.Post("/health", clusterHandler.Health)
		r.Post("/slot", clusterHandler.Slot)
		r.Post("/transaction/fee", clusterHandler.Fee)
		r.Post("/transaction/refresh-blockhash", clusterHandler.RefreshBlockhash)
		r.Post("/transaction/replace-blockhash-with-nonce", clusterHandler.ReplaceBlockhashWithNonce)
		r.Post("/transaction/send", clusterHandler.SendTransaction)
		r.Post("/transaction/simulate", clusterHandler.SimulateTransaction)
		r.Post("/transaction/status", clusterHandler.SignatureStatus)
		r.Post("/version", clusterHandler.Version)
	})

	r.Route("/svm/protocol", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		protocolHandler := misc.NewProtocolHandler()
		r.Post("/rent-exemption/system", protocolHandler.RentExemptionSystem)
		r.Post("/rent-exemption/mint", protocolHandler.RentExemptionMint)
		r.Post("/rent-exemption/token", protocolHandler.RentExemptionToken)
		r.Post("/rent-exemption/stake", protocolHandler.RentExemptionStake)
		r.Post("/rent-exemption/vote", protocolHandler.RentExemptionVote)
		r.Post("/rent-exemption/nonce", protocolHandler.RentExemptionNonce)
		r.Post("/rent-exemption/space", protocolHandler.RentExemptionSpace)
		r.Post("/rent-exemption/public-key", protocolHandler.RentExemptionPublicKey)
	})

	r.Route("/svm/account", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		accountHandler := account.NewAccountHandler()
		r.Post("/state", accountHandler.State)
		r.Post("/owner", accountHandler.Owner)
		r.Post("/authority", accountHandler.Authority)
		r.Post("/balance", accountHandler.Balance)
		r.Post("/airdrop", accountHandler.Airdrop)
		r.Post("/nonce", accountHandler.Nonce)
		r.Post("/tokens", accountHandler.Tokens)
	})

	r.Route("/svm/sign", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		sign := misc.NewSignHandler(cfg)
		r.Post("/", sign.Sign)
		r.Post("/verify", sign.Verify)
		r.Post("/transaction", sign.SignTransaction)
	})

	r.Route("/svm/tool", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		tool := misc.NewToolHandler()
		r.Post("/generate/ed25519-keypair", tool.GenerateKeypair)
		r.Post("/generate/elgamal-keypair", tool.GenerateElGamalKeypair)
		r.Post("/prove/pubkey-validity", tool.ProvePubkeyValidity)
		r.Post("/prove/confidential-transfer", tool.ProveConfidentialTransfer)
		r.Post("/prove/confidential-withdraw", tool.ProveConfidentialWithdraw)
		r.Post("/prove/confidential-empty-account", tool.ProveConfidentialEmptyAccount)
		r.Post("/derive/ae-key-seed-message", tool.AeKeySeedMessage)
		r.Post("/derive/ae-key", tool.DeriveAeKey)
		r.Post("/convert/base58264", tool.ConvertBase58To64)
		r.Post("/convert/base64258", tool.ConvertBase64To58)
	})

	r.Route("/svm/v1", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		tx := v1.NewTransactionHandler(cfg)
		r.Post("/transaction/build", tx.BuildTransaction)
	})

	r.Route("/svm/v2", func(r chi.Router) {
		r.Use(handler.RequireChain(cluster))

		tx := v2.NewSystemTransactionHandler(cfg)
		r.Route("/transaction/system", func(r chi.Router) {
			r.Post("/transfer", tx.SystemTransfer)
			r.Post("/transfer/max", tx.SystemTransferMax)
			r.Post("/transfer/spread", tx.SystemTransferSpread)
			r.Post("/transfer/collect", tx.SystemTransferCollect)
			r.Post("/create-account", tx.SystemCreateAccount)
			r.Post("/allocate", tx.SystemAllocate)
			r.Post("/assign", tx.SystemAssign)
			r.Post("/seed/create-account", tx.SystemSeedCreateAccount)
			r.Post("/seed/transfer", tx.SystemSeedTransfer)
			r.Post("/seed/transfer/max", tx.SystemSeedTransferMax)
			r.Post("/seed/allocate", tx.SystemSeedAllocate)
			r.Post("/seed/assign", tx.SystemSeedAssign)
			r.Post("/nonce/create-account", tx.SystemNonceCreate)
			r.Post("/nonce/initialize", tx.SystemNonceInitialize)
			r.Post("/nonce/advance", tx.SystemNonceAdvance)
			r.Post("/nonce/withdraw", tx.SystemNonceWithdraw)
			r.Post("/nonce/withdraw/max", tx.SystemNonceWithdrawMax)
			r.Post("/nonce/authorize", tx.SystemNonceAuthorize)
			r.Post("/nonce/upgrade", tx.SystemNonceUpgrade)
		})

		tk := v2.NewTokenTransactionHandler(cfg)
		r.Route("/transaction/token", func(r chi.Router) {
			r.Post("/create-mint", tk.CreateMint)
			r.Post("/initialize-mint", tk.InitializeMint)
			r.Post("/initialize-mint2", tk.InitializeMint2)
			r.Post("/initialize-account", tk.InitializeAccount)
			r.Post("/initialize-account2", tk.InitializeAccount2)
			r.Post("/initialize-account3", tk.InitializeAccount3)
			r.Post("/initialize-wrapped-sol", tk.InitializeWrappedSol)
			r.Post("/sync-native", tk.SyncNative)
			r.Post("/unwrap-lamports", tk.UnwrapLamports)
			r.Post("/unwrap-lamports/max", tk.UnwrapLamportsMax)
			r.Post("/initialize-multisig", tk.InitializeMultisig)
			r.Post("/initialize-multisig2", tk.InitializeMultisig2)
			r.Post("/create-multisig", tk.CreateMultisig)
			r.Post("/initialize-immutable-owner", tk.InitializeImmutableOwner)
			r.Post("/create-kta", tk.CreateKTA)
			r.Post("/transfer", tk.Transfer)
			r.Post("/transfer/max", tk.TransferMax)
			r.Post("/approve", tk.Approve)
			r.Post("/approve/max", tk.ApproveMax)
			r.Post("/mint-to", tk.MintTo)
			r.Post("/burn", tk.Burn)
			r.Post("/burn/max", tk.BurnMax)
			r.Post("/mint-to-checked", tk.MintToChecked)
			r.Post("/transfer-checked", tk.TransferChecked)
			r.Post("/transfer-checked/max", tk.TransferCheckedMax)
			r.Post("/burn-checked", tk.BurnChecked)
			r.Post("/burn-checked/max", tk.BurnCheckedMax)
			r.Post("/close-account", tk.CloseAccount)
			r.Post("/withdraw-excess-lamports", tk.WithdrawExcessLamports)
			r.Post("/create-ata", tk.CreateATA)
			r.Post("/create-ata-idempotent", tk.CreateATAIdempotent)
			r.Post("/ata/recover-nested", tk.ATARecoverNested)
			r.Post("/transfer-from-ata", tk.TransferFromATA)
			r.Post("/transfer-from-ata/max", tk.TransferFromATAMax)
			r.Post("/approve-checked", tk.ApproveChecked)
			r.Post("/approve-checked/max", tk.ApproveCheckedMax)
			r.Post("/revoke", tk.Revoke)
			r.Post("/set-authority/mint/replace", tk.SetMintAuthorityReplace)
			r.Post("/set-authority/mint/clear", tk.SetMintAuthorityClear)
			r.Post("/set-authority/freeze/replace", tk.SetFreezeAuthorityReplace)
			r.Post("/set-authority/freeze/clear", tk.SetFreezeAuthorityClear)
			r.Post("/set-authority/owner/replace", tk.SetAccountOwnerReplace)
			r.Post("/set-authority/close/replace", tk.SetCloseAuthorityReplace)
			r.Post("/set-authority/close/clear", tk.SetCloseAuthorityClear)
			r.Post("/freeze-account", tk.FreezeAccount)
			r.Post("/thaw-account", tk.ThawAccount)
			r.Route("/extensions/transfer-fee-config", func(r chi.Router) {
				r.Post("/reallocate", tk.ReallocateTransferFeeConfig)
				r.Post("/initialize", tk.InitializeTransferFeeConfig)
				r.Post("/set", tk.SetTransferFee)
				r.Post("/transfer", tk.TransferCheckedWithFee)
				r.Post("/harvest", tk.HarvestWithheldTokensToMint)
				r.Post("/withdraw-from-mint", tk.WithdrawWithheldTokensFromMint)
				r.Post("/withdraw-from-accounts", tk.WithdrawWithheldTokensFromAccounts)
			})
			r.Route("/extensions/transfer-fee-amount", func(r chi.Router) {
				r.Post("/reallocate", tk.ReallocateTransferFeeAmount)
			})
			r.Route("/extensions/mint-close-authority", func(r chi.Router) {
				r.Post("/reallocate", tk.ReallocateMintCloseAuthority)
				r.Post("/initialize", tk.InitializeMintCloseAuthority)
				r.Post("/replace", tk.SetCloseMintAuthorityReplace)
				r.Post("/clear", tk.SetCloseMintAuthorityClear)
				r.Post("/close", tk.CloseMint)
			})
			r.Route("/extensions/confidential-transfer-mint", func(r chi.Router) {
				r.Post("/reallocate", tk.ReallocateConfidentialTransferMint)
				r.Post("/initialize", tk.InitializeConfidentialTransferMint)
				r.Post("/update", tk.UpdateConfidentialTransferMint)
			})
			r.Route("/extensions/confidential-transfer-account", func(r chi.Router) {
				r.Post("/reallocate", tk.ReallocateConfidentialTransferAccount)
				r.Post("/configure-account", tk.ConfigureAccount)
				r.Post("/approve-account", tk.ApproveAccount)
				r.Post("/deposit", tk.Deposit)
				r.Post("/apply-pending-balance", tk.ApplyPendingBalance)
				r.Post("/transfer", tk.ConfidentialTransfer)
				r.Post("/withdraw", tk.ConfidentialWithdraw)
				r.Post("/empty-account", tk.ConfidentialEmptyAccount)
				r.Post("/enable-confidential-credits", tk.EnableConfidentialCredits)
				r.Post("/disable-confidential-credits", tk.DisableConfidentialCredits)
				r.Post("/enable-non-confidential-credits", tk.EnableNonConfidentialCredits)
				r.Post("/disable-non-confidential-credits", tk.DisableNonConfidentialCredits)
			})
		})

		cb := v2.NewComputeBudgetTransactionHandler(cfg)
		r.Route("/transaction/compute-budget", func(r chi.Router) {
			r.Post("/set-compute-unit-limit", cb.SetComputeUnitLimit)
			r.Post("/set-compute-unit-price", cb.SetComputeUnitPrice)
			r.Post("/request-heap-frame", cb.RequestHeapFrame)
			r.Post("/set-loaded-accounts-data-size-limit", cb.SetLoadedAccountsDataSizeLimit)
		})

		zk := v2.NewZkElgamalProofTransactionHandler(cfg)
		r.Route("/transaction/zk-elgamal-proof", func(r chi.Router) {
			r.Route("/context-state", func(r chi.Router) {
				r.Post("/create/pubkey-validity", zk.ContextStateCreatePubkeyValidity)
				r.Post("/create/ciphertext-commitment-equality", zk.ContextStateCreateCiphertextCommitmentEquality)
				r.Post("/create/batched-grouped-ciphertext-3-handles-validity", zk.ContextStateCreateBatchedGroupedCiphertext3HandlesValidity)
				r.Post("/create/batched-range-proof-u128", zk.ContextStateCreateBatchedRangeProofU128)
				r.Post("/create/zero-ciphertext", zk.ContextStateCreateZeroCiphertext)
				r.Post("/create/ciphertext-ciphertext-equality", zk.ContextStateCreateCiphertextCiphertextEquality)
				r.Post("/create/percentage-with-cap", zk.ContextStateCreatePercentageWithCap)
				r.Post("/create/batched-range-proof-u64", zk.ContextStateCreateBatchedRangeProofU64)
				r.Post("/create/batched-range-proof-u256", zk.ContextStateCreateBatchedRangeProofU256)
				r.Post("/create/grouped-ciphertext-2-handles-validity", zk.ContextStateCreateGroupedCiphertext2HandlesValidity)
				r.Post("/create/batched-grouped-ciphertext-2-handles-validity", zk.ContextStateCreateBatchedGroupedCiphertext2HandlesValidity)
				r.Post("/create/grouped-ciphertext-3-handles-validity", zk.ContextStateCreateGroupedCiphertext3HandlesValidity)
				r.Post("/close", zk.ContextStateClose)
				r.Post("/verify/pubkey-validity", zk.ContextStateVerifyPubkeyValidity)
				r.Post("/verify/ciphertext-commitment-equality", zk.ContextStateVerifyCiphertextCommitmentEquality)
				r.Post("/verify/batched-grouped-ciphertext-3-handles-validity", zk.ContextStateVerifyBatchedGroupedCiphertext3HandlesValidity)
				r.Post("/verify/batched-range-proof-u128", zk.ContextStateVerifyBatchedRangeProofU128)
				r.Post("/verify/zero-ciphertext", zk.ContextStateVerifyZeroCiphertext)
				r.Post("/verify/ciphertext-ciphertext-equality", zk.ContextStateVerifyCiphertextCiphertextEquality)
				r.Post("/verify/percentage-with-cap", zk.ContextStateVerifyPercentageWithCap)
				r.Post("/verify/batched-range-proof-u64", zk.ContextStateVerifyBatchedRangeProofU64)
				r.Post("/verify/batched-range-proof-u256", zk.ContextStateVerifyBatchedRangeProofU256)
				r.Post("/verify/grouped-ciphertext-2-handles-validity", zk.ContextStateVerifyGroupedCiphertext2HandlesValidity)
				r.Post("/verify/batched-grouped-ciphertext-2-handles-validity", zk.ContextStateVerifyBatchedGroupedCiphertext2HandlesValidity)
				r.Post("/verify/grouped-ciphertext-3-handles-validity", zk.ContextStateVerifyGroupedCiphertext3HandlesValidity)
			})
		})
	})

	fmt.Printf("listening on %s\n", cfg.ServerAddr)
	fmt.Printf("swagger at http://localhost%s/swagger/index.html\n", cfg.ServerAddr)

	return http.ListenAndServe(cfg.ServerAddr, r)
}
