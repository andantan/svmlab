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
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
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

	systemProgramID, err := types.NewPublicKeyFromBase58(cfg.Programs.System)
	if err != nil {
		return fmt.Errorf("config: programs.system: %w", err)
	}
	core.System.Init(systemProgramID)

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
		r.Route("/rent-exemption", func(r chi.Router) {
			r.Post("/system", rpcHandler.RentExemptionSystem)
			r.Post("/mint", rpcHandler.RentExemptionMint)
			r.Post("/token", rpcHandler.RentExemptionToken)
			r.Post("/stake", rpcHandler.RentExemptionStake)
			r.Post("/vote", rpcHandler.RentExemptionVote)
			r.Post("/space", rpcHandler.RentExemptionSpace)
			r.Post("/public-key", rpcHandler.RentExemptionPublicKey)
		})
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

		tx := v2.NewTransactionHandler(cfg)
		r.Post("/transaction/system/transfer", tx.SystemTransfer)
		r.Post("/transaction/system/transfer/max", tx.SystemTransferMax)
		r.Post("/transaction/system/create-account", tx.SystemCreateAccount)
		r.Post("/transaction/system/allocate", tx.SystemAllocate)
		r.Post("/transaction/system/assign", tx.SystemAssign)
		r.Post("/transaction/system/seed/create-account", tx.SystemSeedCreateAccount)
		r.Post("/transaction/system/seed/transfer", tx.SystemSeedTransfer)
		r.Post("/transaction/system/seed/transfer/max", tx.SystemSeedTransferMax)
		r.Post("/transaction/system/seed/allocate", tx.SystemSeedAllocate)
		r.Post("/transaction/system/seed/assign", tx.SystemSeedAssign)
	})

	fmt.Printf("listening on %s\n", cfg.ServerAddr)
	fmt.Printf("swagger at http://localhost%s/swagger/index.html\n", cfg.ServerAddr)

	return http.ListenAndServe(cfg.ServerAddr, r)
}
