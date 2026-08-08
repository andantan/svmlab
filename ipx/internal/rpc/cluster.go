package rpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
)

// Chain is one cluster endpoint.
//
// GenesisHash takes the place of evmlab's numeric chain id. It is not part of a
// transaction the way EIP-155 folds a chain id into the signature, so nothing
// stops a signed transaction from being replayed on another cluster that has
// the same account and a live blockhash. It exists to verify at runtime, via
// getGenesisHash, that the endpoint is the cluster the config claims.
type Chain struct {
	Cli         *Client
	Name        string
	Network     string
	GenesisHash *types.Hash
	Symbol      string
	Decimals    uint8
}

type Cluster struct {
	clis map[string]map[string]*Chain
}

func NewCluster(cs []config.Chain) *Cluster {
	clis := make(map[string]map[string]*Chain)
	for _, c := range cs {
		name := strings.ToLower(c.Name)
		network := strings.ToLower(c.Network)

		genesis, err := types.NewHashFromBase58(c.GenesisHash)
		if err != nil {
			panic(fmt.Sprintf("chain %s/%s: invalid genesis hash: %s", name, network, err))
		}

		if clis[name] == nil {
			clis[name] = make(map[string]*Chain)
		}

		clis[name][network] = &Chain{
			Cli:         NewClient(c.RPCURL),
			Name:        name,
			Network:     network,
			GenesisHash: genesis,
			Symbol:      c.NativeCurrency.Symbol,
			Decimals:    c.NativeCurrency.Decimals,
		}
	}

	return &Cluster{
		clis: clis,
	}
}

func (c *Cluster) Get(name, network string) (*Chain, error) {
	ns, ok := c.clis[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported chain: %s", name)
	}

	chain, ok := ns[strings.ToLower(network)]
	if !ok {
		return nil, fmt.Errorf("unsupported chain: %s/%s", name, network)
	}

	return chain, nil
}

type chainCtxKey struct{}

// WithChain returns a context carrying the chain a middleware resolved for
// this request, so handlers read it instead of each resolving it themselves.
func WithChain(ctx context.Context, c *Chain) context.Context {
	return context.WithValue(ctx, chainCtxKey{}, c)
}

// ChainFromContext returns the chain WithChain stored.
//
// An error here means the route is missing the middleware that resolves the
// chain, not a bad request, since that middleware is what makes the chain
// selectable at all.
func ChainFromContext(ctx context.Context) (*Chain, error) {
	c, ok := ctx.Value(chainCtxKey{}).(*Chain)
	if !ok {
		return nil, fmt.Errorf("chain: not present in request context")
	}

	return c, nil
}
