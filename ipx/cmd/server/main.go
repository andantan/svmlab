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
		r.Post("/generate/keypair", tool.GenerateKeypair)
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
			r.Post("/create-kta", tk.CreateKTA)
			r.Post("/mint-to-checked", tk.MintToChecked)
			r.Post("/transfer-checked", tk.TransferChecked)
			r.Post("/burn-checked", tk.BurnChecked)
			r.Post("/close-account", tk.CloseAccount)
			r.Post("/create-ata", tk.CreateATA)
			r.Post("/create-ata-idempotent", tk.CreateATAIdempotent)
			r.Post("/transfer-from-ata", tk.TransferFromATA)
			r.Post("/approve-checked", tk.ApproveChecked)
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
		})
	})

	fmt.Printf("listening on %s\n", cfg.ServerAddr)
	fmt.Printf("swagger at http://localhost%s/swagger/index.html\n", cfg.ServerAddr)

	return http.ListenAndServe(cfg.ServerAddr, r)
}
