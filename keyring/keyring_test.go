// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package keyring

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

var (
	ourPub = mustParsePubKey("03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf")

	message = []byte("happy hanukkah")

	keyLoc = KeyLocator{
		Family: 6,
		Index:  0,
	}

	schnorrSigHex = "71b77d9c8a0badfa7c4eca3fbef5da2a552bf032f56b85fbc5c2f3500498fc20d5ab8505ae9733b1b756da7a5dba41dbe069dd0d86793618829c3077df0cd759"
	schnorrSig, _ = hex.DecodeString(schnorrSigHex)

	requestError = errors.New("error on request")
)

type mockClient struct {
	writeFunc func(string, map[string]interface{}) (*api.Secret, error)
}

func (m *mockClient) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return m.writeFunc(path, data)
}

func newTestKeyRing() *KeyRing {
	return NewKeyRing(
		&mockClient{},
		"03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
		1,
	)
}

func mustParsePubKey(keyHex string) *btcec.PublicKey {
	keyBytes, _ := hex.DecodeString(keyHex)
	key, _ := btcec.ParsePubKey(keyBytes)
	return key
}

func TestECDH(t *testing.T) {
	t.Parallel()

	keyRing := newTestKeyRing()
	client := keyRing.client.(*mockClient)

	peerPubHex := "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e"
	peerPub := mustParsePubKey(peerPubHex)

	keyBytes, _ := hex.DecodeString(
		"7895c217d4f1a33265c0122ce66dd16bcd0b86976198f1128e6dbaef86a2f327",
	)
	var sharedKey [32]byte
	copy(sharedKey[:], keyBytes)

	keyDesc := KeyDescriptor{
		KeyLocator: keyLoc,
		PubKey:     ourPub,
	}

	testCases := []struct {
		name     string
		respData map[string]interface{}
		respErr  error
		key      [32]byte
		err      error
	}{
		{
			name: "ecdh",
			respData: map[string]interface{}{
				"sharedkey": "7895c217d4f1a33265c0122ce66dd16bcd0b86976198f1128e6dbaef86a2f327",
			},
			key: sharedKey,
		},
		{
			name:     ErrNoSharedKeyReturned.Error(),
			respData: map[string]interface{}{},
			err:      ErrNoSharedKeyReturned,
		},
		{
			name: ErrBadSharedKey.Error(),
			respData: map[string]interface{}{
				"sharedkey": "7895",
			},
			err: ErrBadSharedKey,
		},
		{
			name: "shared key not hex",
			respData: map[string]interface{}{
				"sharedkey": "g",
			},
			err: hex.InvalidByteError(0x67),
		},
		{
			name:    "error on request",
			respErr: errors.New("request error"),
			err:     errors.New("request error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client.writeFunc = func(path string,
				data map[string]interface{}) (*api.Secret,
				error) {

				require.Equal(t, "lndsigner/lnd-nodes/ecdh",
					path)

				require.Equal(t, map[string]interface{}{
					"node": keyRing.node,
					"path": []int{2147484665, 2147483649,
						2147483654, 0, 0},
					"peer":   peerPubHex,
					"pubkey": keyRing.node,
				}, data)

				return &api.Secret{Data: testCase.respData},
					testCase.respErr
			}

			key, err := keyRing.ECDH(keyDesc, peerPub)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			require.Equal(t, testCase.key, key)
		})
	}
}

func TestSignMessage(t *testing.T) {
	t.Parallel()

	keyRing := newTestKeyRing()
	client := keyRing.client.(*mockClient)

	testCases := []struct {
		name       string
		doubleHash bool
		compact    bool
		reqData    map[string]interface{}
		respData   map[string]interface{}
		respErr    error
		sig        []byte
		err        error
	}{
		{
			name: "sign single",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			sig: []byte{0xab, 0xcd, 0xef},
		},
		{
			name:       "sign double",
			doubleHash: true,
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa",
				"digest": "2b81484875960ba2eaea16ae0ecfc2848c2d40944b5c034c609ce95542151f14",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			sig: []byte{0xab, 0xcd, 0xef},
		},
		{
			name:    "sign single compact",
			compact: true,
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa-compact",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			sig: []byte{0xab, 0xcd, 0xef},
		},
		{
			name:       "sign double compact",
			doubleHash: true,
			compact:    true,
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa-compact",
				"digest": "2b81484875960ba2eaea16ae0ecfc2848c2d40944b5c034c609ce95542151f14",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			sig: []byte{0xab, 0xcd, 0xef},
		},
		{
			name: "error on request",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respErr: requestError,
			err:     requestError,
		},
		{
			name: ErrNoSignatureReturned.Error(),
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			err: ErrNoSignatureReturned,
		},
		{
			name: "signature not hex",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "ecdsa",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": "g",
			},
			err: hex.InvalidByteError(0x67),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client.writeFunc = func(path string,
				data map[string]interface{}) (*api.Secret,
				error) {

				require.Equal(t, "lndsigner/lnd-nodes/sign",
					path)

				require.Equal(t, testCase.reqData, data)

				return &api.Secret{Data: testCase.respData},
					testCase.respErr
			}

			sig, err := keyRing.SignMessage(keyLoc, message,
				testCase.doubleHash, testCase.compact)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			require.Equal(t, testCase.sig, sig)
		})
	}
}

func TestSignMessageSchnorr(t *testing.T) {
	t.Parallel()

	keyRing := newTestKeyRing()
	client := keyRing.client.(*mockClient)

	testCases := []struct {
		name       string
		doubleHash bool
		tapTweak   []byte
		reqData    map[string]interface{}
		respData   map[string]interface{}
		respErr    error
		sig        []byte
		err        error
	}{
		{
			name: "sign single",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": schnorrSigHex,
			},
			sig: schnorrSig,
		},
		{
			name:       "sign double",
			doubleHash: true,
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "2b81484875960ba2eaea16ae0ecfc2848c2d40944b5c034c609ce95542151f14",
			},
			respData: map[string]interface{}{
				"signature": schnorrSigHex,
			},
			sig: schnorrSig,
		},
		{
			name: "sign single tweaked",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": schnorrSigHex,
			},
			sig: schnorrSig,
		},
		{
			name:       "sign double tweaked",
			doubleHash: true,
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "2b81484875960ba2eaea16ae0ecfc2848c2d40944b5c034c609ce95542151f14",
			},
			respData: map[string]interface{}{
				"signature": schnorrSigHex,
			},
			sig: schnorrSig,
		},
		{
			name: "error on request",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respErr: requestError,
			err:     requestError,
		},
		{
			name: ErrNoSignatureReturned.Error(),
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			err: ErrNoSignatureReturned,
		},
		{
			name: "signature not hex",
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": "g",
			},
			err: hex.InvalidByteError(0x67),
		},
		{
			name: schnorr.ErrSigTooShort.Error(),
			reqData: map[string]interface{}{
				"node": keyRing.node,
				"path": []int{2147484665, 2147483649,
					2147483654, 0, 0},
				"method": "schnorr",
				"digest": "4eacd1f26fe18294c9671e427240e6762e6f021f1e35793cab2850cbec7320f3",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			err: schnorr.Error{
				Err:         schnorr.ErrSigTooShort,
				Description: "malformed signature: too short: 3 < 64",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client.writeFunc = func(path string,
				data map[string]interface{}) (*api.Secret,
				error) {

				require.Equal(t, "lndsigner/lnd-nodes/sign",
					path)

				require.Equal(t, testCase.reqData, data)

				return &api.Secret{Data: testCase.respData},
					testCase.respErr
			}

			sig, err := keyRing.SignMessageSchnorr(keyLoc, message,
				testCase.doubleHash, testCase.tapTweak)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			require.Equal(t, testCase.sig, sig.Serialize())
		})
	}
}

func TestSignPsbt(t *testing.T) {
	t.Parallel()

	keyRing := newTestKeyRing()
	client := keyRing.client.(*mockClient)

	testCases := []struct {
		name     string
		packet   *psbt.Packet
		reqData  map[string]interface{}
		respData map[string]interface{}
		respErr  error
		inputs   []uint32
		err      error
	}{
		{
			name: "nil PSBT",
			err:  errors.New("PSBT packet cannot be nil"),
		},
		{
			name:   "p2tr spend",
			packet: p2trPsbt,
			reqData: map[string]interface{}{
				"node":     keyRing.node,
				"digest":   "6a14f55652583393923a9f6909c9be3ada3e5bd724c324d8a554b823388491ad",
				"path":     []int{2147483734, 2147483648, 2147483648, 0, 0},
				"method":   "schnorr",
				"taptweak": "",
			},
			respData: map[string]interface{}{
				"signature": schnorrSigHex,
			},
			inputs: []uint32{0},
		},
		{
			name:   "p2wkh spend",
			packet: p2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "2046c479fa1d00033ff7239086071cb4abadc2c99e2dd14e6e1af7ed8060f3ca",
				"path":   []int{2147483732, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respData: map[string]interface{}{
				"pubkey":    "abcdef",
				"signature": "abcdef",
			},
			inputs: []uint32{0},
		},
		{
			name:   "np2wkh spend",
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respData: map[string]interface{}{
				"pubkey":    "abcdef",
				"signature": "abcdef",
			},
			inputs: []uint32{0},
		},
		{
			name:   "ln1tweak spend",
			packet: tweak1Psbt,
			reqData: map[string]interface{}{
				"node":     keyRing.node,
				"digest":   "acf17dc76b84ab1b061f274ccea1b680e7195d34f138c92bec64f66a6ed11b7c",
				"ln1tweak": "cf374dcf99541cff08176226b16e1848eee7f00430da428a74ddc671224bbe8f",
				"path":     []int{2147484665, 2147483649, 2147483650, 0, 0},
				"method":   "ecdsa",
			},
			respData: map[string]interface{}{
				"pubkey":    "abcdef",
				"signature": "abcdef",
			},
			inputs: []uint32{0},
		},
		{
			name:   ErrNoPubkeyReturned.Error(),
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respData: map[string]interface{}{
				"signature": "abcdef",
			},
			err: ErrNoPubkeyReturned,
		},
		{
			name:   "pubkey not hex",
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respData: map[string]interface{}{
				"pubkey":    "g",
				"signature": "abcdef",
			},
			err: hex.InvalidByteError(0x67),
		},
		{
			name:   "p2wkh and np2wkh error on request",
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respErr: requestError,
			err:     requestError,
		},
		{
			name:   "np2wkh and p2wkh " + ErrNoSignatureReturned.Error(),
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			err: ErrNoSignatureReturned,
		},
		{
			name:   "np2wkh and p2wkh signature not hex",
			packet: np2wkhPsbt,
			reqData: map[string]interface{}{
				"node":   keyRing.node,
				"digest": "5f5c0b1eb31d60a15c0b607ee037b97bbb2ef375d127be13c4718ddc5b67dc70",
				"path":   []int{2147483697, 2147483648, 2147483648, 0, 0},
				"method": "ecdsa",
			},
			respData: map[string]interface{}{
				"signature": "g",
			},
			err: hex.InvalidByteError(0x67),
		},
		{
			name:   "p2wkh and np2wkh error on request",
			packet: p2trPsbt,
			reqData: map[string]interface{}{
				"node":     keyRing.node,
				"digest":   "6a14f55652583393923a9f6909c9be3ada3e5bd724c324d8a554b823388491ad",
				"path":     []int{2147483734, 2147483648, 2147483648, 0, 0},
				"method":   "schnorr",
				"taptweak": "",
			},
			respErr: requestError,
			err:     requestError,
		},
		{
			name:   "p2tr " + ErrNoSignatureReturned.Error(),
			packet: p2trPsbt,
			reqData: map[string]interface{}{
				"node":     keyRing.node,
				"digest":   "6a14f55652583393923a9f6909c9be3ada3e5bd724c324d8a554b823388491ad",
				"path":     []int{2147483734, 2147483648, 2147483648, 0, 0},
				"method":   "schnorr",
				"taptweak": "",
			},
			err: ErrNoSignatureReturned,
		},
		{
			name:   "p2tr signature not hex",
			packet: p2trPsbt,
			reqData: map[string]interface{}{
				"node":     keyRing.node,
				"digest":   "6a14f55652583393923a9f6909c9be3ada3e5bd724c324d8a554b823388491ad",
				"path":     []int{2147483734, 2147483648, 2147483648, 0, 0},
				"method":   "schnorr",
				"taptweak": "",
			},
			respData: map[string]interface{}{
				"signature": "g",
			},
			err: hex.InvalidByteError(0x67),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client.writeFunc = func(path string,
				data map[string]interface{}) (*api.Secret,
				error) {

				require.Equal(t, "lndsigner/lnd-nodes/sign",
					path)

				require.Equal(t, testCase.reqData, data)

				return &api.Secret{Data: testCase.respData},
					testCase.respErr
			}

			signed, err := keyRing.SignPsbt(testCase.packet)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			require.Equal(t, testCase.inputs, signed)
		})
	}
}

func mustGetPacket(pb64 string) *psbt.Packet {
	packet, _ := psbt.NewFromRawBytes(bytes.NewBuffer([]byte(pb64)), true)
	return packet
}

var (
	p2trPsbt   = mustGetPacket("cHNidP8BAF4CAAAAAReb7pdpQYTQ2CNhvICbAlIE+1c/c+mDcoMwoc8rinenAAAAAAAAAAAAAUbL9QUAAAAAIlEgtfY28ZYCnRSLF8t3TlIu/whJ6214cNnzljDTT1efhbXlCwAAAAEA9gIAAAAAAQFJMZAOE1PK+T6HTes4eGZLMIDd0bzYEZ1oFJVYK/ZiCwAAAAAA/f///wIA4fUFAAAAACJRILX2NvGWAp0UixfLd05SLv8ISetteHDZ85Yw009Xn4W1nR0NjwAAAAAiUSDDFLNZISF+rpRN7aK0J7JM0mT5fqTEKvFKaUMBEw6ZIAJHMEQCIHHymwJU7u3YG6DRJHEBXU7WM7iKpfEyi2RirHkkG3qgAiBlFw4ueMJ7R9UiX7X4kqOkrtnPPbjRFAcV0N2dlwMsqQEhAlwtWnotMY/75da30kBFv6MAP1cQ9+JAtFPHOys8EcVx5AsAAAEBKwDh9QUAAAAAIlEgtfY28ZYCnRSLF8t3TlIu/whJ6214cNnzljDTT1efhbUiBgPNayRhLVP0LyNSLfBQl/5mzCRF1JJj0XfEHSRXn2ocYBgAAAAAVgAAgAAAAIAAAACAAAAAAAAAAAAhFs1rJGEtU/QvI1It8FCX/mbMJEXUkmPRd8QdJFefahxgGQAAAAAAVgAAgAAAAIAAAACAAAAAAAAAAAAAAA==")
	p2wkhPsbt  = mustGetPacket("cHNidP8BAFICAAAAAY5F4ge3IcjdMnXPFvSlcsJtrWsucxdANZMwuxiBAn9mAAAAAAAAAAAAAXWi9QUAAAAAFgAU9Pc1yrjv1bubTE9iLVshd6CQcBPnCwAAAAEAlgIAAAAAAQFFycXtfec9d3aq5MGiwljDzXdT1b27wxA35E5bQ+fjlgAAAAAAAAAAAAHkt/UFAAAAABYAFPT3Ncq479W7m0xPYi1bIXegkHATAUB2zaC2OeERmiGxi78tR1hE7aDCWUJCMhcSvcs4e7kxarTGXy2IcLzCGuwsJkWiYmcunFp6VQSbpcO23KQNMDkz5gsAAAEBH+S39QUAAAAAFgAU9Pc1yrjv1bubTE9iLVshd6CQcBMBAwQBAAAAAQUWABT09zXKuO/Vu5tMT2ItWyF3oJBwEyIGAwEIoLvhEXJvhEZtTcYV/qv1mWWy6gvKBE+dVfZTNiRDGAAAAABUAACAAAAAgAAAAIAAAAAAAAAAAAAA")
	np2wkhPsbt = mustGetPacket("cHNidP8BAFMCAAAAAd5zNp3onh0tGqfG/uWxkO492bU81losB9X4NeyTzD+/AAAAAAAAAAAAAV1w9QUAAAAAF6kUraCbn6aZpvU7PJsguxGajtIBNxOH6QsAAAABAMECAAAAAAEBZd+rb8GaP6GGqU8L9mbFsIQhZg5Tu74ydSOG3Co97GQAAAAAAAAAAAAB1Iz1BQAAAAAXqRStoJufppmm9Ts8myC7EZqO0gE3E4cCSDBFAiEAnd6DdDpgIBspLqYb4c4UxA0OfHH5U6v8MdFqYNGr3qsCICz6j4z50tyrlb6udEg19obEMvxZYapfiTm8b1u+yY7WASEDAQigu+ERcm+ERm1NxhX+q/WZZbLqC8oET51V9lM2JEPoCwAAAQEg1Iz1BQAAAAAXqRStoJufppmm9Ts8myC7EZqO0gE3E4cBAwQBAAAAAQQXFgAUZHoOpcJIIpm9ZZqp4+yUqUbVxlABBRYAFGR6DqXCSCKZvWWaqePslKlG1cZQIgYCjY4A5/M2NnFkZxRH38ob8I0kLvCMqAaLpjV2L4W2DV4YAAAAADEAAIAAAACAAAAAgAAAAAAAAAAAAAA=")
	tweak1Psbt = mustGetPacket("cHNidP8BAF4CAAAAAefBDVMh9KyBaUQgDsjV6nUylfgrye5+zKxHOWe2WppIAgAAAAABAAAAAYgTAAAAAAAAIgAgnt22lI7xTfZhaVvG98+/a2fgGpKGx4If+tDif9TNGtIbDAAAAAEBK4gTAAAAAAAAIgAgh3mqXWpXMnilHq2jlNLT1RHiQblrGAcXso10qnIuHo4BAwSDAAAAAQWIdqkUSL7Vs9GdmmyMm/jAw3NWT1cavGSHY6xnIQM9249K7owaTOry2WiTfm5kYbSiKpopzl0v4REiL4tjk3yCASCHZHVSfCEDCrYgRP5lJXfOS1ZXS110yioIRjDn5OEr6yCLWXhajChSrmepFL5fYOxnPqaCwyQdgixZKou3K8d1iKxoUbJ1aCIGA0fj8run5YT4j5ZwAwgD7jOWCKVLiFP7xPUeSQVQotAvGAAAAAD5AwCAAQAAgAIAAIAAAAAAAAAAAAFRIM83Tc+ZVBz/CBdiJrFuGEju5/AEMNpCinTdxnEiS76PAAA=")
)
