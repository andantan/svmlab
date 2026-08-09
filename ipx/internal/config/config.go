package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is what actually varies between deployments.
//
// Program ids and sysvar addresses were once here and are not any more. They
// are the same on every cluster, so configuring them added no reach and one
// failure mode: a typo in a base58 address parses cleanly and only surfaces as
// a rejected transaction. They now live in core as constants.
type Config struct {
	ServerAddr string  `yaml:"server_addr"`
	Chains     []Chain `yaml:"chain"`
	Keys       []Key   `yaml:"keys"`
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
