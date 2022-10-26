// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package vault

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// MaxAcctID is the number of accounts/key families to create on
	// initialization.
	MaxAcctID = 255

	Bip0043purpose = 1017
	NodeKeyAcct    = 6
)

var (
	// defaultPurposes is a list of non-LN(1017) purposes for which we
	// should create a m/purpose'/0'/0' account as well as their default
	// address types.
	defaultPurposes = []struct {
		purpose   uint32
		addrType  string
		hdVersion [2][4]byte
	}{
		{
			purpose:  49,
			addrType: "HYBRID_NESTED_WITNESS_PUBKEY_HASH",
			hdVersion: [2][4]byte{
				[4]byte{0x04, 0x9d, 0x7c, 0xb2}, // ypub
				[4]byte{0x04, 0x4a, 0x52, 0x62}, // upub
			},
		},
		{
			purpose:  84,
			addrType: "WITNESS_PUBKEY_HASH",
			hdVersion: [2][4]byte{
				[4]byte{0x04, 0xb2, 0x47, 0x46}, // zpub
				[4]byte{0x04, 0x5f, 0x1c, 0xf6}, // vpub
			},
		},
		{
			purpose:  86,
			addrType: "TAPROOT_PUBKEY",
			hdVersion: [2][4]byte{
				[4]byte{0x04, 0x88, 0xb2, 0x1e}, // xpub
				[4]byte{0x04, 0x35, 0x87, 0xcf}, // tpub
			},
		},
	}
)

type backend struct {
	*framework.Backend
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "lnd-nodes/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.listNodes,
				logical.UpdateOperation: b.createNode,
				logical.CreateOperation: b.createNode,
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
					Default: 1,
				},
			},
		},
		&framework.Path{
			Pattern: "lnd-nodes/accounts/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.listAccounts,
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
		},
		&framework.Path{
			Pattern: "lnd-nodes/ecdh/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.ecdh,
				logical.CreateOperation: b.ecdh,
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
		},
		&framework.Path{
			Pattern: "lnd-nodes/sign/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.derivePubKey,
				logical.UpdateOperation: b.deriveAndSign,
				logical.CreateOperation: b.deriveAndSign,
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
		},
	}
}
