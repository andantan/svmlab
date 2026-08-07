package rpc

import (
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
)

// Programs holds the well-known program ids, parsed once at startup.
//
// This is where evmlab keeps an address book per chain. Here it hangs off the
// cluster instead, since the ids are identical on every Solana cluster.
type Programs struct {
	System          *types.PublicKey
	ComputeBudget   *types.PublicKey
	Token           *types.PublicKey
	Token2022       *types.PublicKey
	AssociatedToken *types.PublicKey
	Memo            *types.PublicKey
	Stake           *types.PublicKey
	Vote            *types.PublicKey
}

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
	Programs    *Programs
}

type Cluster struct {
	clis     map[string]map[string]*Chain
	programs *Programs
}

func NewCluster(cs []config.Chain, ps config.Programs) *Cluster {
	programs := &Programs{
		System:          mustProgram("system", ps.System),
		ComputeBudget:   mustProgram("compute_budget", ps.ComputeBudget),
		Token:           mustProgram("token", ps.Token),
		Token2022:       mustProgram("token_2022", ps.Token2022),
		AssociatedToken: mustProgram("associated_token", ps.AssociatedToken),
		Memo:            mustProgram("memo", ps.Memo),
		Stake:           mustProgram("stake", ps.Stake),
		Vote:            mustProgram("vote", ps.Vote),
	}

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
			Programs:    programs,
		}
	}

	return &Cluster{
		clis:     clis,
		programs: programs,
	}
}

func mustProgram(field, id string) *types.PublicKey {
	if id == "" {
		return nil
	}

	k, err := types.NewPublicKeyFromBase58(id)
	if err != nil {
		panic(fmt.Sprintf("programs.%s: invalid program id: %s", field, err))
	}

	return k
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

func (c *Cluster) Programs() *Programs {
	return c.programs
}
