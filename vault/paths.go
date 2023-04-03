// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package vault

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// TODO(aakselrod): expand text documentation throughout this file where
// fields are available, in order to auto-generate docs.
func wrapOp(f framework.OperationFunc) framework.OperationHandler {
	return &framework.PathOperation{
		Callback: f,
	}
}

func (b *backend) basePath() *framework.Path {
	return &framework.Path{
		Pattern: "lnd-nodes/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   wrapOp(b.listNodes),
			logical.UpdateOperation: wrapOp(b.createNode),
		},
		HelpSynopsis: "Create and list LND nodes",
		HelpDescription: `

GET  - list all node pubkeys and coin types for HD derivations
POST - generate a new node seed and store it indexed by node pubkey

`,
		Fields: map[string]*framework.FieldSchema{
			"network": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "Network, one of " +
					"'mainnet', 'testnet', " +
					"'simnet', 'signet', or " +
					"'regtest'",
				Default: "regtest",
			},
		},
	}
}

func (b *backend) importPath() *framework.Path {
	return &framework.Path{
		Pattern: "lnd-nodes/import/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: wrapOp(b.importNode),
		},
		HelpSynopsis: "Import existing LND node into vault",
		HelpDescription: `

POST - import existing LND node into vault with seedphrase and passphrase

`,
		Fields: map[string]*framework.FieldSchema{
			"node": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: node pubkey, " +
					"must be 66 hex characters",
				Default: "",
			},
			"network": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "Network, one of " +
					"'mainnet', 'testnet', " +
					"'simnet', 'signet', or " +
					"'regtest'",
				Default: "regtest",
			},
			"seedphrase": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "seed phrase to import, " +
					"use instead of seed",
				Default: "",
			},
			"passphrase": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: passphrase, " +
					"use only with seed phrase",
				Default: "",
			},
		},
	}
}

func (b *backend) accountsPath() *framework.Path {
	return &framework.Path{
		Pattern: "lnd-nodes/accounts/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: wrapOp(b.listAccounts),
		},
		HelpSynopsis: "List accounts for import into LND " +
			"watch-only node",
		HelpDescription: `

GET - list all node accounts in JSON format suitable for import into watch-
only LND

`,
		Fields: map[string]*framework.FieldSchema{
			"node": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "node pubkey, must be " +
					"66 hex characters",
				Default: "",
			},
		},
	}
}

func (b *backend) ecdhPath() *framework.Path {
	return &framework.Path{
		Pattern: "lnd-nodes/ecdh/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: wrapOp(b.ecdh),
		},
		HelpSynopsis: "ECDH derived privkey with peer pubkey",
		HelpDescription: `

POST - ECDH the privkey derived with the submitted path with the specified
peer pubkey

`,
		Fields: map[string]*framework.FieldSchema{
			"node": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "node pubkey, must be " +
					"66 hex characters",
				Default: "",
			},
			"path": &framework.FieldSchema{
				Type: framework.TypeCommaIntSlice,
				Description: "derivation path, with " +
					"the first 3 elements " +
					"being hardened",
				Default: []int{},
			},
			"pubkey": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: pubkey for " +
					"which to do ECDH, checked " +
					"against derived pubkey to " +
					"ensure a match",
				Default: "",
			},
			"peer": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "pubkey for ECDH peer, " +
					"must be 66 hex characters",
				Default: "",
			},
		},
	}
}

func (b *backend) signPath() *framework.Path {
	return &framework.Path{
		Pattern: "lnd-nodes/sign/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   wrapOp(b.derivePubKey),
			logical.UpdateOperation: wrapOp(b.deriveAndSign),
		},
		HelpSynopsis: "Derive pubkeys and sign with privkeys",
		HelpDescription: `

GET  - return the pubkey derived with the submitted path
POST - sign a digest with the method specified using the privkey derived with
the submitted path

`,
		Fields: map[string]*framework.FieldSchema{
			"node": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "node pubkey, must be " +
					"66 hex characters",
				Default: "",
			},
			"path": &framework.FieldSchema{
				Type: framework.TypeCommaIntSlice,
				Description: "derivation path, with " +
					"the first 3 elements " +
					"being hardened",
				Default: []int{},
			},
			"digest": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "digest to sign, must " +
					"be hex-encoded 32 bytes",
				Default: "",
			},
			"method": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "signing method: " +
					"one of: ecdsa, " +
					"ecdsa-compact, or schnorr",
				Default: "",
			},
			"pubkey": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: pubkey for " +
					"which to sign, checked " +
					"against derived pubkey to " +
					"ensure a match",
				Default: "",
			},
			"taptweak": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: hex-encoded " +
					"taproot tweak",
				Default: "",
			},
			"ln1tweak": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: hex-encoded " +
					"LN single commit tweak",
				Default: "",
			},
			"ln2tweak": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "optional: hex-encoded " +
					"LN double revocation tweak",
				Default: "",
			},
		},
	}
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		b.basePath(),
		b.importPath(),
		b.accountsPath(),
		b.ecdhPath(),
		b.signPath(),
	}
}
