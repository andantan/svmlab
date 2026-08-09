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
	"github.com/andantan/svmlab/api/handler/misc"
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
		r.Post("/health", rpcHandler.Health)
		r.Post("/version", rpcHandler.Version)
		r.Post("/slot", rpcHandler.Slot)
		r.Post("/genesis-hash", rpcHandler.GenesisHash)
		r.Post("/blockhash", rpcHandler.BlockHash)
		r.Post("/balance", rpcHandler.Balance)
		r.Post("/account", rpcHandler.Account)
		r.Post("/account/owner", rpcHandler.AccountOwner)
		r.Post("/nonce", rpcHandler.Nonce)
		r.Post("/rent-exemption/system", rpcHandler.RentExemptionSystem)
		r.Post("/rent-exemption/mint", rpcHandler.RentExemptionMint)
		r.Post("/rent-exemption/token", rpcHandler.RentExemptionToken)
		r.Post("/rent-exemption/stake", rpcHandler.RentExemptionStake)
		r.Post("/rent-exemption/vote", rpcHandler.RentExemptionVote)
		r.Post("/rent-exemption/nonce", rpcHandler.RentExemptionNonce)
		r.Post("/rent-exemption/space", rpcHandler.RentExemptionSpace)
		r.Post("/rent-exemption/public-key", rpcHandler.RentExemptionPublicKey)
		r.Post("/fee", rpcHandler.Fee)
		r.Post("/airdrop", rpcHandler.Airdrop)
		r.Post("/transaction/send", rpcHandler.SendTransaction)
		r.Post("/transaction/simulate", rpcHandler.SimulateTransaction)
		r.Post("/transaction/status", rpcHandler.SignatureStatus)
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
			r.Post("/transfer/many", tx.SystemTransferMany)
			r.Post("/transfer/batch", tx.SystemTransferBatch)
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
	})

	fmt.Printf("listening on %s\n", cfg.ServerAddr)
	fmt.Printf("swagger at http://localhost%s/swagger/index.html\n", cfg.ServerAddr)

	return http.ListenAndServe(cfg.ServerAddr, r)
}
