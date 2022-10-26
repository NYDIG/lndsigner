// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) listAccounts(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	acctList := "{\n    \"accounts\": [\n"

	listAccount := func(purpose, coin, act uint32, addrType string,
		version []byte) (string, error) {

		strListing := ""

		// Derive purpose.
		purposeKey, err := rootKey.DeriveNonStandard(
			purpose + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return "", err
		}
		defer purposeKey.Zero()

		// Derive coin.
		coinKey, err := purposeKey.DeriveNonStandard(
			coin + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return "", err
		}
		defer coinKey.Zero()

		// Derive account.
		actKey, err := coinKey.DeriveNonStandard(
			act + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return "", err
		}
		defer actKey.Zero()

		// Get account watch-only pubkey.
		xPub, err := actKey.Neuter()
		if err != nil {
			return "", err
		}

		// Ensure we get the right HDVersion for the account key.
		if version != nil {
			xPub, err = xPub.CloneWithVersion(version)
			if err != nil {
				return "", err
			}
		}

		strPurpose := fmt.Sprintf("%d", purpose)
		strCoin := fmt.Sprintf("%d", coin)
		strAct := fmt.Sprintf("%d", act)

		strListing += "        {\n"

		strListing += "            \"name\": \""
		if act == 0 {
			strListing += "default"
		} else {
			strListing += "act:" + strAct
		}
		strListing += "\",\n"

		strListing += "            \"address_type\": \"" + addrType +
			"\",\n"

		strListing += "            \"extended_public_key\": \"" +
			xPub.String() + "\",\n"

		strListing += "            \"master_key_fingerprint\": null,\n"

		strListing += "            \"derivation_path\": \"m/" +
			strPurpose + "'/" + strCoin + "'/" + strAct + "'\",\n"

		strListing += "            \"external_key_count\": 0,\n"

		strListing += "            \"internal_key_count\": 0,\n"

		strListing += "            \"watch_only\": false\n"

		strListing += "        }"

		return strListing, nil
	}

	for _, acctInfo := range defaultPurposes {
		strListing, err := listAccount(
			acctInfo.purpose,
			0,
			0,
			acctInfo.addrType,
			acctInfo.hdVersion[net.HDCoinType][:],
		)
		if err != nil {
			b.Logger().Error("Failed to derive default account",
				"node", strNode, "err", err)
			return nil, err
		}

		acctList += strListing + ",\n"
	}

	for act := uint32(0); act <= MaxAcctID; act++ {
		strListing, err := listAccount(
			Bip0043purpose,
			net.HDCoinType,
			act,
			"WITNESS_PUBKEY_HASH",
			nil,
		)
		if err != nil {
			b.Logger().Error("Failed to derive Lightning account",
				"node", strNode, "err", err)
			return nil, err
		}

		acctList += strListing

		if act < MaxAcctID {
			acctList += ","
		}

		acctList += "\n"
	}

	acctList += "    ]\n}"

	return &logical.Response{
		Data: map[string]interface{}{
			"acctList": acctList,
		},
	}, nil
}

func (b *backend) ecdh(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	peerPubHex := data.Get("peer").(string)
	if len(peerPubHex) != 2*btcec.PubKeyBytesLenCompressed {
		b.Logger().Error("Peer pubkey is wrong length",
			"peer", peerPubHex)
		return nil, errors.New("invalid peer pubkey")
	}

	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		b.Logger().Error("Failed to decode peer pubkey hex",
			"error", err)
		return nil, err
	}

	peerPubKey, err := btcec.ParsePubKey(peerPubBytes)
	if err != nil {
		b.Logger().Error("Failed to parse peer pubkey",
			"error", err)
		return nil, err
	}

	var (
		pubJacobian btcec.JacobianPoint
		s           btcec.JacobianPoint
	)
	peerPubKey.AsJacobian(&pubJacobian)

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	privKey, err := derivePrivKey(seed, net, data.Get("path").([]int))
	if err != nil {
		b.Logger().Error("Failed to derive privkey",
			"node", strNode, "error", err)
		return nil, err
	}
	defer privKey.Zero()

	err = checkRequiredPubKey(privKey, data.Get("pubkey").(string))
	if err != nil {
		// We log here as warning because there's no case when we
		// should be using ECDH with a mismatching own key.
		b.Logger().Warn("Pubkey mismatch",
			"node", strNode, "error", err)
		return nil, err
	}

	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		b.Logger().Error("Failed to derive valid ECDSA privkey",
			"node", strNode, "error", err)
		return nil, err
	}
	defer ecPrivKey.Zero()

	btcec.ScalarMultNonConst(&ecPrivKey.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := btcec.NewPublicKey(&s.X, &s.Y)
	h := sha256.Sum256(sPubKey.SerializeCompressed())

	return &logical.Response{
		Data: map[string]interface{}{
			"sharedkey": hex.EncodeToString(h[:]),
		},
	}, nil
}

func (b *backend) derivePubKey(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	pubKey, err := derivePubKey(seed, net, data.Get("path").([]int))
	if err != nil {
		b.Logger().Error("Failed to derive pubkey",
			"node", strNode, "error", err)
		return nil, err
	}

	pubKeyBytes, err := extKeyToPubBytes(pubKey)
	if err != nil {
		b.Logger().Error("derivePubKey: Failed to get pubkey bytes",
			"node", strNode, "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"pubkey": hex.EncodeToString(pubKeyBytes),
		},
	}, nil
}

func (b *backend) deriveAndSign(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	tapTweakHex := data.Get("taptweak").(string)
	singleTweakHex := data.Get("ln1tweak").(string)
	doubleTweakHex := data.Get("ln2tweak").(string)

	numTweaks := int(0)

	if len(singleTweakHex) > 0 {
		numTweaks++
	}
	if len(doubleTweakHex) > 0 {
		numTweaks++
	}

	if numTweaks > 1 {
		b.Logger().Error("Both single and double tweak specified")
		return nil, errors.New("both single and double tweak specified")
	}

	strNode := data.Get("node").(string)

	seed, net, err := b.getNode(ctx, req.Storage, strNode)
	if err != nil {
		b.Logger().Error("Failed to retrieve node info",
			"node", strNode, "error", err)
		return nil, err
	}
	defer zero(seed)

	privKey, err := derivePrivKey(seed, net, data.Get("path").([]int))
	if err != nil {
		b.Logger().Error("Failed to derive privkey",
			"node", strNode, "error", err)
		return nil, err
	}
	defer privKey.Zero()

	err = checkRequiredPubKey(privKey, data.Get("pubkey").(string))
	if err != nil {
		// We log here as info because this is expected when signing
		// a PSBT.
		b.Logger().Info("Pubkey mismatch",
			"node", strNode, "error", err)
		return nil, err
	}

	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		b.Logger().Error("Failed to derive valid ECDSA privkey",
			"node", strNode, "error", err)
		return nil, err
	}
	defer ecPrivKey.Zero()

	signMethod := data.Get("method").(string)

	// Taproot tweak.
	var tapTweakBytes []byte

	if len(tapTweakHex) > 0 {
		tapTweakBytes, err = hex.DecodeString(tapTweakHex)
		if err != nil {
			b.Logger().Error("Couldn't decode taptweak hex",
				"error", err)
			return nil, err
		}
	}

	if signMethod == "schnorr" {
		ecPrivKey = txscript.TweakTaprootPrivKey(
			ecPrivKey,
			tapTweakBytes,
		)
	}

	switch {
	// Single commitment tweak as used by SignPsbt.
	case len(singleTweakHex) > 0:
		singleTweakBytes, err := hex.DecodeString(singleTweakHex)
		if err != nil {
			b.Logger().Error("Couldn't decode ln1tweak hex",
				"error", err)
			return nil, err
		}

		ecPrivKey = tweakPrivKey(
			ecPrivKey,
			singleTweakBytes,
		)

	// Double revocation tweak as used by SignPsbt.
	case len(doubleTweakHex) > 0:
		doubleTweakBytes, err := hex.DecodeString(doubleTweakHex)
		if err != nil {
			b.Logger().Error("Couldn't decode ln2tweak hex",
				"error", err)
			return nil, err
		}

		doubleTweakKey, _ := btcec.PrivKeyFromBytes(doubleTweakBytes)
		ecPrivKey = deriveRevocationPrivKey(ecPrivKey, doubleTweakKey)
	}

	digest := data.Get("digest").(string)
	if len(digest) != 64 {
		b.Logger().Error("Digest is not hex-encoded 32-byte value")
		return nil, errors.New("invalid digest")
	}

	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		b.Logger().Error("Failed to decode digest from hex",
			"error", err)
		return nil, err
	}

	var sigBytes []byte

	// TODO(aakselrod): check derivation paths are sane for the type of
	// signature we're requesting.
	switch signMethod {
	case "ecdsa":
		sigBytes = ecdsa.Sign(ecPrivKey, digestBytes).Serialize()
	case "ecdsa-compact":
		sigBytes, _ = ecdsa.SignCompact(ecPrivKey, digestBytes, true)
	case "schnorr":
		sig, err := schnorr.Sign(ecPrivKey, digestBytes)
		if err != nil {
			b.Logger().Error("Failed to sign digest using Schnorr",
				"node", strNode, "error", err)
			return nil, err
		}

		sigBytes = sig.Serialize()
	default:
		b.Logger().Info("Requested invalid signing method",
			"method", signMethod)
		return nil, errors.New("invalid signing method")
	}

	// We return the pre-tweak pubkey for populating PSBTs and other uses.
	pubKeyBytes, err := extKeyToPubBytes(privKey)
	if err != nil {
		b.Logger().Error("derivePubKey: Failed to get pubkey bytes",
			"node", strNode, "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sigBytes),
			"pubkey":    hex.EncodeToString(pubKeyBytes),
		},
	}, nil
}

func (b *backend) getNode(ctx context.Context, storage logical.Storage,
	id string) ([]byte, *chaincfg.Params, error) {

	if len(id) != 2*btcec.PubKeyBytesLenCompressed {
		return nil, nil, errors.New("invalid node id")
	}

	nodePath := "lnd-nodes/" + id
	entry, err := storage.Get(ctx, nodePath)
	if err != nil {
		return nil, nil, err
	}

	if entry == nil {
		return nil, nil, errors.New("node not found")
	}

	if len(entry.Value) <= hdkeychain.RecommendedSeedLen {
		return nil, nil, errors.New("got invalid seed from storage")
	}

	net, err := getNet(string(entry.Value[hdkeychain.RecommendedSeedLen:]))
	if err != nil {
		return nil, nil, err
	}

	return entry.Value[:hdkeychain.RecommendedSeedLen], net, nil
}

func (b *backend) listNodes(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	nodes, err := req.Storage.List(ctx, "lnd-nodes/")
	if err != nil {
		b.Logger().Error("Failed to retrieve the list of nodes",
			"error", err)
		return nil, err
	}

	respData := make(map[string]interface{})
	for _, node := range nodes {
		seed, net, err := b.getNode(ctx, req.Storage, node)
		if err != nil {
			b.Logger().Error("Failed to retrieve node info",
				"node", node, "error", err)
			return nil, err
		}
		defer zero(seed)

		respData[node] = int(net.HDCoinType)
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) createNode(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	strNet := data.Get("network").(string)
	net, err := getNet(strNet)
	if err != nil {
		b.Logger().Error("Failed to parse network", "error", err)
		return nil, err
	}

	var seed []byte
	defer zero(seed)

	err = hdkeychain.ErrUnusableSeed
	for err == hdkeychain.ErrUnusableSeed {
		seed, err = hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen,
		)
	}
	if err != nil {
		b.Logger().Error("Failed to generate new LND seed",
			"error", err)
		return nil, err
	}

	nodePubKey, err := derivePubKey(seed, net, []int{
		int(Bip0043purpose + hdkeychain.HardenedKeyStart),
		int(net.HDCoinType + hdkeychain.HardenedKeyStart),
		int(NodeKeyAcct + hdkeychain.HardenedKeyStart),
		0,
		0,
	})
	if err != nil {
		b.Logger().Error("Failed to derive node pubkey from LND seed",
			"error", err)
		return nil, err
	}

	pubKeyBytes, err := extKeyToPubBytes(nodePubKey)
	if err != nil {
		b.Logger().Error("createNode: Failed to get pubkey bytes",
			"error", err)
		return nil, err
	}

	strPubKey := hex.EncodeToString(pubKeyBytes)
	nodePath := "lnd-nodes/" + strPubKey

	seed = append(seed, []byte(strNet)...)
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:      nodePath,
		Value:    seed,
		SealWrap: true,
	})
	if err != nil {
		b.Logger().Error("Failed to save seed for node",
			"error", err)
		return nil, err
	}

	b.Logger().Info("Wrote new LND node seed", "pubkey", strPubKey)

	return &logical.Response{
		Data: map[string]interface{}{
			"node": strPubKey,
		},
	}, nil
}

func getNet(strNet string) (*chaincfg.Params, error) {
	switch strNet {
	/*case "mainnet":
	return &chaincfg.MainNetParams, nil
	*/
	case "testnet":
		return &chaincfg.TestNet3Params, nil

	case "simnet":
		return &chaincfg.SimNetParams, nil

	case "signet":
		return &chaincfg.SigNetParams, nil

	case "regtest":
		return &chaincfg.RegressionNetParams, nil

	default:
		return nil, errors.New("invalid network specified: " + strNet)
	}
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend,
	error) {

	var b backend
	b.Backend = &framework.Backend{
		Help:  "",
		Paths: framework.PathAppend(b.paths()),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"lnd-nodes/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}

	return &b, nil
}
