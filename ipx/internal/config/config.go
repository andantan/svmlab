package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerAddr string   `yaml:"server_addr"`
	Programs   Programs `yaml:"programs"`
	Sysvars    Sysvars  `yaml:"sysvars"`
	Chains     []Chain  `yaml:"chain"`
	Keys       []Key    `yaml:"keys"`
}

// Programs holds the well-known native and SPL program IDs.
//
// Unlike EVM utility contracts, these addresses are identical on every
// Solana cluster, so they are declared once instead of per-chain.
//
// All of them are required, including ones no endpoint reaches yet. Because
// none of them vary by cluster, an empty field is a truncated config rather
// than a deliberate omission, and is better caught at startup than on the
// first request that happens to need it.
type Programs struct {
	System          string `yaml:"system"`
	ComputeBudget   string `yaml:"compute_budget"`
	Token           string `yaml:"token"`
	Token2022       string `yaml:"token_2022"`
	AssociatedToken string `yaml:"associated_token"`
	Memo            string `yaml:"memo"`
	Stake           string `yaml:"stake"`
	Vote            string `yaml:"vote"`
}

// Sysvars holds the accounts the runtime keeps cluster state in.
//
// They are addresses like the program ids above and are equally invariant, but
// they are not programs: nothing is invoked at them. They are passed as
// ordinary read-only accounts to instructions that need to see the state they
// hold, which is why several nonce instructions take them.
type Sysvars struct {
	RecentBlockhashes string `yaml:"recent_blockhashes"`
	Rent              string `yaml:"rent"`
}

// Chain describes a single Solana cluster.
//
// Solana has no chain id. A cluster is identified by its genesis hash,
// which can be verified against the getGenesisHash RPC method.
type Chain struct {
	Name           string         `yaml:"name"`
	Network        string         `yaml:"network"`
	GenesisHash    string         `yaml:"genesis_hash"`
	NativeCurrency NativeCurrency `yaml:"native_currency"`
	RPCURL         string         `yaml:"rpc"`
}

type NativeCurrency struct {
	Symbol   string `yaml:"symbol"`
	Decimals uint8  `yaml:"decimals"`
}

// Key is a local development keypair.
//
// PublicKey is the base58-encoded 32-byte ed25519 public key, which on
// Solana is the account address itself. PrivateKey is the base58-encoded
// 64-byte expanded secret key in [seed 32 || public_key 32] form, so the
// public key is redundant and exists only to be cross-checked at load time.
type Key struct {
	Alias      string `yaml:"alias"`
	PublicKey  string `yaml:"public_key"`
	PrivateKey string `yaml:"private_key"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("config: server_addr is required")
	}
	if cfg.Programs.System == "" {
		return nil, fmt.Errorf("config: programs.system is required")
	}
	if cfg.Programs.ComputeBudget == "" {
		return nil, fmt.Errorf("config: programs.compute_budget is required")
	}
	if cfg.Programs.Token == "" {
		return nil, fmt.Errorf("config: programs.token is required")
	}
	if cfg.Programs.Token2022 == "" {
		return nil, fmt.Errorf("config: programs.token_2022 is required")
	}
	if cfg.Programs.AssociatedToken == "" {
		return nil, fmt.Errorf("config: programs.associated_token is required")
	}
	if cfg.Programs.Memo == "" {
		return nil, fmt.Errorf("config: programs.memo is required")
	}
	if cfg.Programs.Stake == "" {
		return nil, fmt.Errorf("config: programs.stake is required")
	}
	if cfg.Programs.Vote == "" {
		return nil, fmt.Errorf("config: programs.vote is required")
	}
	if cfg.Sysvars.RecentBlockhashes == "" {
		return nil, fmt.Errorf("config: sysvars.recent_blockhashes is required")
	}
	if cfg.Sysvars.Rent == "" {
		return nil, fmt.Errorf("config: sysvars.rent is required")
	}
	if len(cfg.Chains) == 0 {
		return nil, fmt.Errorf("config: at least one chain is required")
	}
	for i, chain := range cfg.Chains {
		if chain.Name == "" {
			return nil, fmt.Errorf("config: chain[%d].name is required", i)
		}
		if chain.Network == "" {
			return nil, fmt.Errorf("config: chain[%d].network is required", i)
		}
		if chain.GenesisHash == "" {
			return nil, fmt.Errorf("config: chain[%d].genesis_hash is required", i)
		}
		if chain.RPCURL == "" {
			return nil, fmt.Errorf("config: chain[%d].rpc is required", i)
		}
	}
	for i, key := range cfg.Keys {
		if key.Alias == "" {
			return nil, fmt.Errorf("config: keys[%d].alias is required", i)
		}
		if key.PublicKey == "" {
			return nil, fmt.Errorf("config: keys[%d].public_key is required", i)
		}
		if key.PrivateKey == "" {
			return nil, fmt.Errorf("config: keys[%d].private_key is required", i)
		}
	}

	return &cfg, nil
}

func (c *Config) ChainByNameNetwork(name, network string) (*Chain, error) {
	for i := range c.Chains {
		if c.Chains[i].Name == name && c.Chains[i].Network == network {
			return &c.Chains[i], nil
		}
	}
	return nil, fmt.Errorf("config: chain %q/%q not found", name, network)
}

// KeyByPublicKey looks up a keypair by its base58 address.
//
// The comparison is case-sensitive: base58 is not a case-folding encoding,
// and two addresses differing only in case are distinct accounts.
func (c *Config) KeyByPublicKey(publicKey string) (*Key, error) {
	for i := range c.Keys {
		if c.Keys[i].PublicKey == publicKey {
			return &c.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("config: key with public key %q not found", publicKey)
}

func (c *Config) KeyByAlias(alias string) (*Key, error) {
	for i := range c.Keys {
		if c.Keys[i].Alias == alias {
			return &c.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("config: key with alias %q not found", alias)
}
