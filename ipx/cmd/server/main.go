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

	v1 "github.com/andantan/svmlab/api/handler/v1"
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

	cluster := rpc.NewCluster(cfg.Chains, cfg.Programs)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/svm/v1", func(r chi.Router) {
		tx := v1.NewTransactionHandler(cluster)
		r.Post("/transaction/build", tx.BuildTransaction)
		r.Post("/transaction/sign", tx.SignTransaction)
		r.Post("/transaction/send", tx.SendTransaction)
	})

	fmt.Printf("listening on %s\n", cfg.ServerAddr)
	fmt.Printf("swagger at http://localhost%s/swagger/index.html\n", cfg.ServerAddr)

	return http.ListenAndServe(cfg.ServerAddr, r)
}
