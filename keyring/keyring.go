// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package keyring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/hashicorp/vault/api"
	"github.com/nydig/lndsigner/vault"
)

// signMethod defines the different ways a signer can sign, given a specific
// input.
type signMethod uint8

const (
	// WitnessV0SignMethod denotes that a SegWit v0 (p2wkh, np2wkh, p2wsh)
	// input script should be signed.
	witnessV0SignMethod signMethod = 0

	// TaprootKeySpendBIP0086SignMethod denotes that a SegWit v1 (p2tr)
	// input should be signed by using the BIP0086 method (commit to
	// internal key only).
	taprootKeySpendBIP0086SignMethod signMethod = 1

	// TaprootKeySpendSignMethod denotes that a SegWit v1 (p2tr)
	// input should be signed by using a given taproot hash to commit to in
	// addition to the internal key.
	taprootKeySpendSignMethod signMethod = 2

	// TaprootScriptSpendSignMethod denotes that a SegWit v1 (p2tr) input
	// should be spent using the script path and that a specific leaf script
	// should be signed for.
	taprootScriptSpendSignMethod signMethod = 3
)

var (
	// psbtKeyTypeInputSignatureTweakSingle is a custom/proprietary PSBT key
	// for an input that specifies what single tweak should be applied to
	// the key before signing the input. The value 51 is leet speak for
	// "si", short for "single".
	psbtKeyTypeInputSignatureTweakSingle = []byte{0x51}

	// psbtKeyTypeInputSignatureTweakDouble is a custom/proprietary PSBT key
	// for an input that specifies what double tweak should be applied to
	// the key before signing the input. The value d0 is leet speak for
	// "do", short for "double".
	psbtKeyTypeInputSignatureTweakDouble = []byte{0xd0}
)

type KeyLocator struct {
	// Family is the family of key being identified.
	Family uint32

	// Index is the precise index of the key being identified.
	Index uint32
}

type KeyDescriptor struct {
	// KeyLocator is the internal KeyLocator of the descriptor.
	KeyLocator

	// PubKey is an optional public key that fully describes a target key.
	// If this is nil, the KeyLocator MUST NOT be empty.
	PubKey *btcec.PublicKey
}

// logicalWriter is an interface that specifies the relevant methods of the
// vault/api.Logical struct for mocking in tests.
type logicalWriter interface {
	Write(string, map[string]interface{}) (*api.Secret, error)
}

// KeyRing is an HD keyring backed by pre-derived in-memory account keys from
// which index keys can be quickly derived on demand.
type KeyRing struct {
	client logicalWriter
	node   string
	coin   uint32
}

// NewKeyRing returns a vault-backed key ring.
func NewKeyRing(client logicalWriter, node string, coin uint32) *KeyRing {
	return &KeyRing{
		client: client,
		node:   node,
		coin:   coin,
	}
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// target key descriptor and remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx := k*P s := sha256(sx.SerializeCompressed())
func (k *KeyRing) ECDH(keyDesc KeyDescriptor, pub *btcec.PublicKey) ([32]byte,
	error) {

	reqData := map[string]interface{}{
		"node": k.node,
		"path": []int{
			int(vault.Bip0043purpose +
				hdkeychain.HardenedKeyStart),
			int(k.coin + hdkeychain.HardenedKeyStart),
			int(keyDesc.Family + hdkeychain.HardenedKeyStart),
			0, // Only external branch in LN purpose.
			int(keyDesc.Index),
		},
		"peer": hex.EncodeToString(pub.SerializeCompressed()),
	}

	if keyDesc.PubKey != nil {
		reqData["pubkey"] = hex.EncodeToString(
			keyDesc.PubKey.SerializeCompressed(),
		)
	}

	log.Debugf("Sending data %+v for shared key request", reqData)

	sharedKeyResp, err := k.client.Write(
		"lndsigner/lnd-nodes/ecdh",
		reqData,
	)
	if err != nil {
		return [32]byte{}, err
	}

	log.Debugf("Got data %+v in shared key response", sharedKeyResp.Data)

	sharedKeyHex, ok := sharedKeyResp.Data["sharedkey"].(string)
	if !ok {
		return [32]byte{}, ErrNoSharedKeyReturned
	}

	sharedKeyBytes, err := hex.DecodeString(sharedKeyHex)
	if err != nil {
		return [32]byte{}, err
	}

	if len(sharedKeyBytes) != 32 {
		return [32]byte{}, ErrBadSharedKey
	}

	var sharedKeyByteArray [32]byte

	copy(sharedKeyByteArray[:], sharedKeyBytes)

	return sharedKeyByteArray, nil
}

// SignMessage signs the given message, single or double SHA256 hashing it
// first, with the private key described in the key locator.
func (k *KeyRing) SignMessage(keyLoc KeyLocator, msg []byte, doubleHash bool,
	compact bool) ([]byte, error) {

	var digest []byte
	if doubleHash {
		digest = chainhash.DoubleHashB(msg)
	} else {
		digest = chainhash.HashB(msg)
	}

	reqData := map[string]interface{}{
		"node": k.node,
		"path": []int{
			int(vault.Bip0043purpose + hdkeychain.HardenedKeyStart),
			int(k.coin + hdkeychain.HardenedKeyStart),
			int(keyLoc.Family + hdkeychain.HardenedKeyStart),
			0, // Only external branch in LN purpose.
			int(keyLoc.Index),
		},
		"method": "ecdsa",
		"digest": hex.EncodeToString(digest),
	}

	if compact {
		reqData["method"] = "ecdsa-compact"
	}

	log.Debugf("Sending data %+v for signing request", reqData)

	signResp, err := k.client.Write(
		"lndsigner/lnd-nodes/sign",
		reqData,
	)
	if err != nil {
		return nil, err
	}

	log.Debugf("Got data %+v in signing response", signResp.Data)

	signatureHex, ok := signResp.Data["signature"].(string)
	if !ok {
		return nil, ErrNoSignatureReturned
	}

	return hex.DecodeString(signatureHex)
}

// SignMessageSchnorr signs the given message, single or double SHA256
// hashing it first, with the private key described in the key locator
// and the optional Taproot tweak applied to the private key.
func (k *KeyRing) SignMessageSchnorr(keyLoc KeyLocator, msg []byte,
	doubleHash bool, taprootTweak []byte) (*schnorr.Signature, error) {

	var digest []byte
	if doubleHash {
		digest = chainhash.DoubleHashB(msg)
	} else {
		digest = chainhash.HashB(msg)
	}

	reqData := map[string]interface{}{
		"node": k.node,
		"path": []int{
			int(vault.Bip0043purpose + hdkeychain.HardenedKeyStart),
			int(k.coin + hdkeychain.HardenedKeyStart),
			int(keyLoc.Family + hdkeychain.HardenedKeyStart),
			0, // Only external branch in LN purpose.
			int(keyLoc.Index),
		},
		"method": "schnorr",
		"digest": hex.EncodeToString(digest),
	}

	if len(taprootTweak) > 0 {
		reqData["taptweak"] = hex.EncodeToString(taprootTweak)
	}

	log.Debugf("Sending data %+v for signing request", reqData)

	signResp, err := k.client.Write(
		"lndsigner/lnd-nodes/sign",
		reqData,
	)
	if err != nil {
		return nil, err
	}

	log.Debugf("Got data %+v in signing response", signResp.Data)

	signatureHex, ok := signResp.Data["signature"].(string)
	if !ok {
		return nil, ErrNoSignatureReturned
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, err
	}

	return schnorr.ParseSignature(signatureBytes)
}

// SignPsbt signs all inputs in the PSBT that can be signed by our keyring.
// We have no state information, so we only attempt to derive the appropriate
// keys for each input and sign if we get a match.
func (k *KeyRing) SignPsbt(packet *psbt.Packet) ([]uint32, error) {
	// In signedInputs we return the indices of psbt inputs that were signed
	// by our wallet. This way the caller can check if any inputs were signed.
	var signedInputs []uint32

	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output.
	err := psbt.VerifyInputOutputLen(packet, true, true)
	if err != nil {
		return nil, err
	}

	strPacket, _ := packet.B64Encode()
	log.Debugf("Got PSBT to sign: %s", strPacket)

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. If there is nothing more to sign or
	// there are inputs that we don't know how to sign, we won't return any
	// error. So it's possible we're not the final signer. We expect all
	// required UTXO data as part of the PSBT packet as we have no state.
	tx := packet.UnsignedTx
	prevOutputFetcher := psbtPrevOutputFetcher(packet)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)
	for idx := range tx.TxIn {
		in := &packet.Inputs[idx]

		// We can only sign if we have UTXO information available. Since
		// we don't finalize, we just skip over any input that we know
		// we can't do anything with. Since we only support signing
		// witness inputs, we only look at the witness UTXO being set.
		if in.WitnessUtxo == nil {
			continue
		}

		// Skip this input if it's got final witness data attached.
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		// Skip this input if there is no BIP32 derivation info
		// available.
		if len(in.Bip32Derivation) == 0 {
			continue
		}

		// What kind of signature is expected from us and do we have all
		// information we need?
		signMethod, err := validateSigningMethod(in)
		if err != nil {
			return nil, err
		}

		switch signMethod {
		// For p2wkh, np2wkh and p2wsh.
		case witnessV0SignMethod:
			err = k.signSegWitV0(in, tx, sigHashes, idx)

		// For p2tr BIP0086 key spend only.
		case taprootKeySpendBIP0086SignMethod:
			rootHash := make([]byte, 0)
			err = k.signSegWitV1KeySpend(
				in, tx, sigHashes, idx, rootHash,
			)

		// For p2tr with script commitment key spend path.
		case taprootKeySpendSignMethod:
			rootHash := in.TaprootMerkleRoot
			err = k.signSegWitV1KeySpend(
				in, tx, sigHashes, idx, rootHash,
			)

		// For p2tr script spend path.
		case taprootScriptSpendSignMethod:
			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			err = k.signSegWitV1ScriptSpend(
				in, tx, sigHashes, idx, leaf,
			)

		default:
			err = fmt.Errorf("unsupported signing method for "+
				"PSBT signing: %v", signMethod)
		}
		if err != nil {
			return nil, err
		}

		signedInputs = append(signedInputs, uint32(idx))
	}

	return signedInputs, nil
}

// signSegWitV0 attempts to generate a signature for a SegWit version 0 input
// and stores it in the PartialSigs (and FinalScriptSig for np2wkh addresses)
// field.
func (k *KeyRing) signSegWitV0(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int) error {

	if len(in.Bip32Derivation) == 0 {
		return nil
	}

	// Extract the correct witness and/or legacy scripts now, depending on
	// the type of input we sign. The txscript package has the peculiar
	// requirement that the PkScript of a P2PKH must be given as the witness
	// script in order for it to arrive at the correct sighash. That's why
	// we call it subScript here instead of witness script.
	subScript := prepareScriptsV0(in)

	// We have everything we need to calculate the digest for signing.
	digest, err := txscript.CalcWitnessSigHash(subScript, sigHashes,
		in.SighashType, tx, idx, in.WitnessUtxo.Value)
	if err != nil {
		return fmt.Errorf("error getting sighash for input %d: %v",
			idx, err)
	}

	log.Debugf("Got input %+v for signing with unknowns %+v", in,
		in.Unknowns)

	reqData := map[string]interface{}{
		"node":   k.node,
		"path":   sliceUint32ToInt(in.Bip32Derivation[0].Bip32Path),
		"method": "ecdsa",
		"digest": hex.EncodeToString(digest),
	}

	getTweakParams(in.Unknowns, reqData)

	log.Debugf("Sending data %+v for signing request", reqData)

	signResp, err := k.client.Write(
		"lndsigner/lnd-nodes/sign",
		reqData,
	)
	if err != nil {
		return err
	}

	log.Debugf("Got data %+v in signing response", signResp.Data)

	signatureHex, ok := signResp.Data["signature"].(string)
	if !ok {
		return ErrNoSignatureReturned
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return err
	}

	pubKeyHex, ok := signResp.Data["pubkey"].(string)
	if !ok {
		return ErrNoPubkeyReturned
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return err
	}

	in.PartialSigs = append(in.PartialSigs, &psbt.PartialSig{
		PubKey:    pubKeyBytes,
		Signature: append(signatureBytes, byte(in.SighashType)),
	})

	return nil
}

// signSegWitV1KeySpend attempts to generate a signature for a SegWit version 1
// (p2tr) input and stores it in the TaprootKeySpendSig field.
func (k *KeyRing) signSegWitV1KeySpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int,
	tapscriptRootHash []byte) error {

	if len(in.Bip32Derivation) == 0 {
		return nil
	}

	digest, err := txscript.CalcTaprootSignatureHash(
		sigHashes, in.SighashType, tx, idx,
		txscript.NewCannedPrevOutputFetcher(
			in.WitnessUtxo.PkScript,
			in.WitnessUtxo.Value,
		),
	)
	if err != nil {
		return err
	}

	reqData := map[string]interface{}{
		"node":     k.node,
		"path":     sliceUint32ToInt(in.Bip32Derivation[0].Bip32Path),
		"method":   "schnorr",
		"digest":   hex.EncodeToString(digest),
		"taptweak": hex.EncodeToString(tapscriptRootHash),
	}

	getTweakParams(in.Unknowns, reqData)

	log.Debugf("Sending data %+v for signing request", reqData)

	signResp, err := k.client.Write(
		"lndsigner/lnd-nodes/sign",
		reqData,
	)
	if err != nil {
		return err
	}

	signatureHex, ok := signResp.Data["signature"].(string)
	if !ok {
		return ErrNoSignatureReturned
	}

	log.Debugf("Got data %+v in signing response", signResp.Data)

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return err
	}

	in.TaprootKeySpendSig = append(signatureBytes, byte(in.SighashType))

	return nil
}

// signSegWitV1ScriptSpend attempts to generate a signature for a SegWit version
// 1 (p2tr) input and stores it in the TaprootScriptSpendSig field.
func (k *KeyRing) signSegWitV1ScriptSpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, leaf txscript.TapLeaf) error {

	if len(in.Bip32Derivation) == 0 {
		return nil
	}

	digest, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, in.SighashType, tx, idx,
		txscript.NewCannedPrevOutputFetcher(
			in.WitnessUtxo.PkScript,
			in.WitnessUtxo.Value,
		),
		leaf,
	)
	if err != nil {
		return err
	}

	reqData := map[string]interface{}{
		"node":   k.node,
		"path":   sliceUint32ToInt(in.Bip32Derivation[0].Bip32Path),
		"method": "schnorr",
		"digest": hex.EncodeToString(digest),
	}

	getTweakParams(in.Unknowns, reqData)

	log.Debugf("Sending data %+v for signing request", reqData)

	signResp, err := k.client.Write(
		"lndsigner/lnd-nodes/sign",
		reqData,
	)
	if err != nil {
		return err
	}

	log.Debugf("Got data %+v in signing response", signResp.Data)

	signatureHex, ok := signResp.Data["signature"].(string)
	if !ok {
		return ErrNoSignatureReturned
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return err
	}

	leafHash := leaf.TapHash()
	in.TaprootScriptSpendSig = append(
		in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: in.TaprootBip32Derivation[0].XOnlyPubKey,
			LeafHash:    leafHash[:],
			Signature:   signatureBytes,
			SigHash:     in.SighashType,
		},
	)

	return nil
}

// prepareScriptsV0 returns the appropriate witness v0 and/or legacy scripts,
// depending on the type of input that should be signed.
func prepareScriptsV0(in *psbt.PInput) []byte {
	switch {
	// It's a NP2WKH input:
	//case len(in.RedeemScript) > 0:
	//	return in.RedeemScript

	// It's a P2WSH input:
	case len(in.WitnessScript) > 0:
		return in.WitnessScript

	// It's a P2WKH input:
	default:
		return in.WitnessUtxo.PkScript
	}
}

// getTweakParams examines if there are any tweak parameters given in the
// custom/proprietary PSBT fields and adds them to a vault request's data
// to use them if populated.
func getTweakParams(unknowns []*psbt.Unknown, reqData map[string]interface{}) {
	// There can be other custom/unknown keys in a PSBT that we just ignore.
	// Key tweaking is optional and only one tweak (single _or_ double) can
	// ever be applied (at least for any use cases described in the BOLT
	// spec).
	for _, u := range unknowns {
		if bytes.Equal(u.Key, psbtKeyTypeInputSignatureTweakSingle) {
			reqData["ln1tweak"] = hex.EncodeToString(u.Value)
			return
		}

		if bytes.Equal(u.Key, psbtKeyTypeInputSignatureTweakDouble) {
			reqData["ln2tweak"] = hex.EncodeToString(u.Value)
			return
		}
	}
}

// validateSigningMethod attempts to detect the signing method that is required
// to sign for the given PSBT input and makes sure all information is available
// to do so.
func validateSigningMethod(in *psbt.PInput) (signMethod, error) {
	script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
	if err != nil {
		return 0, fmt.Errorf("error detecting signing method, "+
			"couldn't parse pkScript: %v", err)
	}

	switch script.Class() {
	case txscript.WitnessV0PubKeyHashTy, txscript.ScriptHashTy,
		txscript.WitnessV0ScriptHashTy:

		return witnessV0SignMethod, nil

	case txscript.WitnessV1TaprootTy:
		if len(in.TaprootBip32Derivation) == 0 {
			return 0, fmt.Errorf("cannot sign for taproot input " +
				"without taproot BIP0032 derivation info")
		}

		// Currently, we only support creating one signature per input.
		if len(in.TaprootBip32Derivation) > 1 {
			return 0, fmt.Errorf("unsupported multiple taproot " +
				"BIP0032 derivation info found, can only " +
				"sign for one at a time")
		}

		derivation := in.TaprootBip32Derivation[0]
		switch {
		// No leaf hashes means this is the internal key we're signing
		// with, so it's a key spend. And no merkle root means this is
		// a BIP0086 output we're signing for.
		case len(derivation.LeafHashes) == 0 &&
			len(in.TaprootMerkleRoot) == 0:

			return taprootKeySpendBIP0086SignMethod, nil

		// A non-empty merkle root means we committed to a taproot hash
		// that we need to use in the tap tweak.
		case len(derivation.LeafHashes) == 0:
			// Getting here means the merkle root isn't empty, but
			// is it exactly the length we need?
			if len(in.TaprootMerkleRoot) != sha256.Size {
				return 0, fmt.Errorf("invalid taproot merkle "+
					"root length, got %d expected %d",
					len(in.TaprootMerkleRoot), sha256.Size)
			}

			return taprootKeySpendSignMethod, nil

		// Currently, we only support signing for one leaf at a time.
		case len(derivation.LeafHashes) == 1:
			// If we're supposed to be signing for a leaf hash, we
			// also expect the leaf script that hashes to that hash
			// in the appropriate field.
			if len(in.TaprootLeafScript) != 1 {
				return 0, fmt.Errorf("specified leaf hash in " +
					"taproot BIP0032 derivation but " +
					"missing taproot leaf script")
			}

			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			leafHash := leaf.TapHash()
			if !bytes.Equal(leafHash[:], derivation.LeafHashes[0]) {
				return 0, fmt.Errorf("specified leaf hash in" +
					"taproot BIP0032 derivation but " +
					"corresponding taproot leaf script " +
					"was not found")
			}

			return taprootScriptSpendSignMethod, nil

		default:
			return 0, fmt.Errorf("unsupported number of leaf " +
				"hashes in taproot BIP0032 derivation info, " +
				"can only sign for one at a time")
		}

	default:
		return 0, fmt.Errorf("unsupported script class for signing "+
			"PSBT: %v", script.Class())
	}
}

// psbtPrevOutputFetcher returns a txscript.PrevOutFetcher built from the UTXO
// information in a PSBT packet.
func psbtPrevOutputFetcher(packet *psbt.Packet) *txscript.MultiPrevOutFetcher {
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for idx, txIn := range packet.UnsignedTx.TxIn {
		in := packet.Inputs[idx]

		// Skip any input that has no UTXO.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			continue
		}

		if in.NonWitnessUtxo != nil {
			prevIndex := txIn.PreviousOutPoint.Index
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint,
				in.NonWitnessUtxo.TxOut[prevIndex],
			)

			continue
		}

		// Fall back to witness UTXO only for older wallets.
		if in.WitnessUtxo != nil {
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint, in.WitnessUtxo,
			)
		}
	}

	return fetcher
}

func sliceUint32ToInt(uints []uint32) []int {
	ints := make([]int, len(uints))

	for idx, element := range uints {
		ints[idx] = int(element)
	}

	return ints
}
