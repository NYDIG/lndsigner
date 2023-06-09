// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
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
		return ErrPubkeyMismatch
	}

	return nil
}

func derivePrivKey(seed []byte, net *chaincfg.Params,
	derivationPath []int) (*hdkeychain.ExtendedKey, error) {

	if len(derivationPath) != 5 {
		return nil, ErrWrongLengthDerivationPath
	}

	derPath := make([]uint32, 5)

	for idx, element := range derivationPath {
		if element < 0 {
			return nil, ErrNegativeElement
		}

		if element > math.MaxUint32 {
			return nil, ErrElementOverflow
		}

		if idx < 3 && element < hdkeychain.HardenedKeyStart {
			return nil, ErrElementNotHardened
		}

		derPath[idx] = uint32(element)
	}

	rootKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	// Derive purpose. We do these derivations with DeriveNonStandard to
	// match btcwallet's (and thus lnd's) usage as shown here:
	// https://github.com/btcsuite/btcwallet/blob/c314de6995500686c93716037f2279128cc1e9e8/waddrmgr/manager.go#L1459
	purposeKey, err := rootKey.DeriveNonStandard( // nolint:staticcheck
		derPath[0],
	)
	if err != nil {
		return nil, err
	}
	defer purposeKey.Zero()

	// Derive coin type.
	coinTypeKey, err := purposeKey.DeriveNonStandard( // nolint:staticcheck
		derPath[1],
	)
	if err != nil {
		return nil, err
	}
	defer coinTypeKey.Zero()

	// Derive account.
	accountKey, err := coinTypeKey.DeriveNonStandard( // nolint:staticcheck
		derPath[2],
	)
	if err != nil {
		return nil, err
	}
	defer accountKey.Zero()

	// Derive branch.
	branchKey, err := accountKey.DeriveNonStandard( // nolint:staticcheck
		derPath[3],
	)
	if err != nil {
		return nil, err
	}
	defer branchKey.Zero()

	// Derive index.
	indexKey, err := branchKey.DeriveNonStandard( // nolint:staticcheck
		derPath[4],
	)
	if err != nil {
		return nil, err
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
