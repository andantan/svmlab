package handler

import (
	"net/http"
	"strings"

	"github.com/andantan/svmlab/internal/rpc"
)

// ChainNameHeader and ChainNetworkHeader select a cluster per-request.
//
// They are headers rather than body fields because the chain is what a
// request routes to, not data the request carries: the same body can be
// replayed against a different cluster, but the header changes which
// infrastructure answers it.
const (
	ChainNameHeader    = "X-Chain-Name"
	ChainNetworkHeader = "X-Chain-Network"
)

// RequireChain resolves the cluster a request targets from its headers and
// stores it in the request context, so handlers read it back with
// rpc.ChainFromContext instead of each resolving it themselves.
func RequireChain(cluster *rpc.Cluster) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimSpace(r.Header.Get(ChainNameHeader))
			if name == "" {
				WriteError(w, http.StatusBadRequest, ChainNameHeader+" header is required")
				return
			}
			network := strings.TrimSpace(r.Header.Get(ChainNetworkHeader))
			if network == "" {
				WriteError(w, http.StatusBadRequest, ChainNetworkHeader+" header is required")
				return
			}

			chain, err := cluster.Get(name, network)
			if err != nil {
				WriteError(w, http.StatusBadRequest, err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(rpc.WithChain(r.Context(), chain)))
		})
	}
}
