// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nydig/lndsigner/keyring"
	"github.com/nydig/lndsigner/proto"
	"github.com/nydig/lndsigner/vault"
)

// Server is a sub-server of the main RPC server: the signer RPC. This sub RPC
// server allows external callers to access the full signing capabilities of
// lndsignerd. This allows callers to create custom protocols, external to the
// signer itself, even backed by multiple distinct signers across independent
// failure domains.
type signerServer struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	proto.UnimplementedSignerServer

	server *rpcServer
}

// A compile time check to ensure that Server fully implements the SignerServer
// gRPC service.
var _ proto.SignerServer = (*signerServer)(nil)

// SignMessage signs a message with the key specified in the key locator. The
// returned signature is fixed-size LN wire format encoded.
func (s *signerServer) SignMessage(_ context.Context,
	in *proto.SignMessageReq) (*proto.SignMessageResp, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("a message to sign MUST be passed in")
	}
	if in.KeyLoc == nil {
		return nil, fmt.Errorf("a key locator MUST be passed in")
	}
	if in.SchnorrSig && in.CompactSig {
		return nil, fmt.Errorf("compact format can not be used for " +
			"Schnorr signatures")
	}

	// Describe the private key we'll be using for signing.
	keyLocator := keyring.KeyLocator{
		Family: uint32(in.KeyLoc.KeyFamily),
		Index:  uint32(in.KeyLoc.KeyIndex),
	}

	// Use the schnorr signature algorithm to sign the message.
	if in.SchnorrSig {
		sig, err := s.server.keyRing.SignMessageSchnorr(
			keyLocator, in.Msg, in.DoubleHash,
			in.SchnorrSigTapTweak,
		)
		if err != nil {
			return nil, fmt.Errorf("can't sign the hash: %v", err)
		}

		sigParsed, err := schnorr.ParseSignature(sig.Serialize())
		if err != nil {
			return nil, fmt.Errorf("can't parse Schnorr "+
				"signature: %v", err)
		}

		return &proto.SignMessageResp{
			Signature: sigParsed.Serialize(),
		}, nil
	}

	// Create the raw ECDSA signature first and convert it to the final wire
	// format after.
	sig, err := s.server.keyRing.SignMessage(
		keyLocator, in.Msg, in.DoubleHash, in.CompactSig,
	)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}
	return &proto.SignMessageResp{
		Signature: sig,
	}, nil
}

// DeriveSharedKey returns a shared secret key by performing Diffie-Hellman key
// derivation between the ephemeral public key in the request and the node's
// key specified in the key_desc parameter. Either a key locator or a raw public
// key is expected in the key_desc, if neither is supplied, defaults to the
// node's identity private key. The old key_loc parameter in the request
// shouldn't be used anymore.
// The resulting shared public key is serialized in the compressed format and
// hashed with sha256, resulting in the final key length of 256bit.
func (s *signerServer) DeriveSharedKey(ctx context.Context,
	in *proto.SharedKeyRequest) (*proto.SharedKeyResponse, error) {

	// Check that EphemeralPubkey is valid.
	ephemeralPubkey, err := parseRawKeyBytes(in.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("error in ephemeral pubkey: %v", err)
	}
	if ephemeralPubkey == nil {
		return nil, fmt.Errorf("must provide ephemeral pubkey")
	}

	// When key_desc is used, the key_desc.key_loc is expected as the caller
	// needs to specify the KeyFamily.
	if in.KeyDesc != nil && in.KeyDesc.KeyLoc == nil {
		return nil, fmt.Errorf("when setting key_desc the field " +
			"key_desc.key_loc must also be set")
	}

	// We extract two params, rawKeyBytes and keyLoc.
	rawKeyBytes := in.KeyDesc.GetRawKeyBytes()
	keyLoc := in.KeyDesc.GetKeyLoc()

	// When no keyLoc is supplied, defaults to the node's identity private
	// key.
	if keyLoc == nil {
		keyLoc = &proto.KeyLocator{
			KeyFamily: int32(vault.NodeKeyAcct),
			KeyIndex:  0,
		}
	}

	// Check the caller is using either the key index or the raw public key
	// to perform the ECDH, we can't have both.
	if rawKeyBytes != nil && keyLoc.KeyIndex != 0 {
		return nil, fmt.Errorf("use either raw_key_bytes or key_index")
	}

	// Check the raw public key is valid. Notice that if the rawKeyBytes is
	// empty, the parseRawKeyBytes won't return an error, a nil
	// *btcec.PublicKey is returned instead.
	pk, err := parseRawKeyBytes(rawKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error in raw pubkey: %v", err)
	}

	// Create a key descriptor. When the KeyIndex is not specified, it uses
	// the empty value 0, and when the raw public key is not specified, the
	// pk is nil.
	keyDescriptor := keyring.KeyDescriptor{
		KeyLocator: keyring.KeyLocator{
			Family: uint32(keyLoc.KeyFamily),
			Index:  uint32(keyLoc.KeyIndex),
		},
		PubKey: pk,
	}

	// Derive the shared key using ECDH and hashing the serialized
	// compressed shared point.
	sharedKeyHash, err := s.server.keyRing.ECDH(
		keyDescriptor, ephemeralPubkey,
	)
	if err != nil {
		signerLog.Errorf("unable to derive shared key: %+v", err)
		return nil, err
	}

	return &proto.SharedKeyResponse{SharedKey: sharedKeyHash[:]}, nil
}

// parseRawKeyBytes checks that the provided raw public key is valid and returns
// the public key. A nil public key is returned if the length of the rawKeyBytes
// is zero.
func parseRawKeyBytes(rawKeyBytes []byte) (*btcec.PublicKey, error) {
	switch {
	case len(rawKeyBytes) == 33:
		// If a proper raw key was provided, then we'll attempt
		// to decode and parse it.
		return btcec.ParsePubKey(rawKeyBytes)

	case len(rawKeyBytes) == 0:
		// No key is provided, return nil.
		return nil, nil

	default:
		// If the user provided a raw key, but it's of the
		// wrong length, then we'll return with an error.
		return nil, fmt.Errorf("pubkey must be " +
			"serialized in compressed format if " +
			"specified")
	}
}
