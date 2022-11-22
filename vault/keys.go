// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

func extKeyToPubBytes(key *hdkeychain.ExtendedKey) ([]byte, error) {
	ecPubKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	return ecPubKey.SerializeCompressed(), nil
}

func checkRequiredPubKey(derived *hdkeychain.ExtendedKey,
	required string) error {

	if required == "" {
		return nil
	}

	pubKeyBytes, err := extKeyToPubBytes(derived)
	if err != nil {
		return err
	}

	requiredBytes, err := hex.DecodeString(required)
	if err != nil {
		return err
	}

	if !bytes.Equal(requiredBytes, pubKeyBytes) {
		return fmt.Errorf("pubkey mismatch: wanted %x, got %x",
			requiredBytes, pubKeyBytes)
	}

	return nil
}

func derivePrivKey(seed []byte, net *chaincfg.Params,
	derivationPath []int) (*hdkeychain.ExtendedKey, error) {

	if len(derivationPath) != 5 {
		return nil, errors.New("derivation path not 5 elements")
	}

	derPath := make([]uint32, 5)

	for idx, element := range derivationPath {
		if element < 0 {
			return nil, errors.New("negative derivation path " +
				"element")
		}

		if element > math.MaxUint32 {
			return nil, errors.New("derivation path element > " +
				"MaxUint32")
		}

		if idx < 3 && element < hdkeychain.HardenedKeyStart {
			return nil, fmt.Errorf("element at index %d is not "+
				"hardened", idx)
		}

		derPath[idx] = uint32(element)
	}

	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	// Derive purpose.
	purposeKey, err := rootKey.DeriveNonStandard(
		derPath[0],
	)
	if err != nil {
		return nil, errors.New("error deriving purpose")
	}
	defer purposeKey.Zero()

	// Derive coin type.
	coinTypeKey, err := purposeKey.DeriveNonStandard(
		derPath[1],
	)
	if err != nil {
		return nil, errors.New("error deriving coin type")
	}
	defer coinTypeKey.Zero()

	// Derive account.
	accountKey, err := coinTypeKey.DeriveNonStandard(
		derPath[2],
	)
	if err != nil {
		return nil, errors.New("error deriving account")
	}
	defer accountKey.Zero()

	// Derive branch.
	branchKey, err := accountKey.DeriveNonStandard(derPath[3])
	if err != nil {
		return nil, errors.New("error deriving branch")
	}
	defer branchKey.Zero()

	// Derive index.
	indexKey, err := branchKey.DeriveNonStandard(derPath[4])
	if err != nil {
		return nil, errors.New("error deriving index")
	}

	return indexKey, nil
}

func derivePubKey(seed []byte, net *chaincfg.Params, derivationPath []int) (
	*hdkeychain.ExtendedKey, error) {

	privKey, err := derivePrivKey(seed, net, derivationPath)
	if err != nil {
		return nil, err
	}

	return privKey.Neuter()
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}

// tweakPrivKey tweaks the private key of a public base point given a per
// commitment point. The per commitment secret is the revealed revocation
// secret for the commitment state in question. This private key will only need
// to be generated in the case that a channel counter party broadcasts a
// revoked state. Precisely, the following operation is used to derive a
// tweaked private key:
//
//   - tweakPriv := basePriv + sha256(commitment || basePub) mod N
//
// Where N is the order of the sub-group.
func tweakPrivKey(basePriv *btcec.PrivateKey,
	commitTweak []byte) *btcec.PrivateKey {

	// tweakInt := sha256(commitPoint || basePub)
	tweakScalar := new(btcec.ModNScalar)
	tweakScalar.SetByteSlice(commitTweak)

	tweakScalar.Add(&basePriv.Key)

	return &btcec.PrivateKey{Key: *tweakScalar}
}

// singleTweakBytes computes set of bytes we call the single tweak. The purpose
// of the single tweak is to randomize all regular delay and payment base
// points. To do this, we generate a hash that binds the commitment point to
// the pay/delay base point. The end end results is that the basePoint is
// tweaked as follows:
//
//   - key = basePoint + sha256(commitPoint || basePoint)*G
func singleTweakBytes(commitPoint, basePoint *btcec.PublicKey) []byte {
	h := sha256.New()
	h.Write(commitPoint.SerializeCompressed())
	h.Write(basePoint.SerializeCompressed())
	return h.Sum(nil)
}

// deriveRevocationPrivKey derives the revocation private key given a node's
// commitment private key, and the preimage to a previously seen revocation
// hash. Using this derived private key, a node is able to claim the output
// within the commitment transaction of a node in the case that they broadcast
// a previously revoked commitment transaction.
//
// The private key is derived as follows:
//
//	revokePriv := (revokeBasePriv * sha256(revocationBase || commitPoint)) +
//	              (commitSecret * sha256(commitPoint || revocationBase)) mod N
//
// Where N is the order of the sub-group.
func deriveRevocationPrivKey(revokeBasePriv *btcec.PrivateKey,
	commitSecret *btcec.PrivateKey) *btcec.PrivateKey {

	// r = sha256(revokeBasePub || commitPoint)
	revokeTweakBytes := singleTweakBytes(
		revokeBasePriv.PubKey(), commitSecret.PubKey(),
	)
	revokeTweakScalar := new(btcec.ModNScalar)
	revokeTweakScalar.SetByteSlice(revokeTweakBytes)

	// c = sha256(commitPoint || revokeBasePub)
	commitTweakBytes := singleTweakBytes(
		commitSecret.PubKey(), revokeBasePriv.PubKey(),
	)
	commitTweakScalar := new(btcec.ModNScalar)
	commitTweakScalar.SetByteSlice(commitTweakBytes)

	// Finally to derive the revocation secret key we'll perform the
	// following operation:
	//
	//  k = (revocationPriv * r) + (commitSecret * c) mod N
	//
	// This works since:
	//  P = (G*a)*b + (G*c)*d
	//  P = G*(a*b) + G*(c*d)
	//  P = G*(a*b + c*d)
	revokeHalfPriv := revokeTweakScalar.Mul(&revokeBasePriv.Key)
	commitHalfPriv := commitTweakScalar.Mul(&commitSecret.Key)

	revocationPriv := revokeHalfPriv.Add(commitHalfPriv)

	return &btcec.PrivateKey{Key: *revocationPriv}
}
