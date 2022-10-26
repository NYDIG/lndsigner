// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"bytes"
	"context"
	"fmt"

	"github.com/bottlepay/lndsigner/keyring"
	"github.com/bottlepay/lndsigner/proto"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	// macPermissions maps RPC calls to the permissions they require.
	walletPermissions = map[string][]bakery.Op{
		"/proto.WalletKit/SignPsbt": {{
			Entity: "onchain",
			Action: "write",
		}},
	}
)

// walletKit is a sub-RPC server that exposes a tool kit which allows clients
// to execute common wallet operations. This includes requesting new addresses,
// keys (for contracts!), and publishing transactions.
type walletKit struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	proto.UnimplementedWalletKitServer

	server *rpcServer
}

// A compile time check to ensure that walletKit fully implements the
// proto.WalletKitServer gRPC service.
var _ proto.WalletKitServer = (*walletKit)(nil)

// SignPsbt expects a partial transaction with all inputs and outputs fully
// declared and tries to sign all unsigned inputs that have all required fields
// (UTXO information, BIP32 derivation information, witness or sig scripts)
// set.
// If no error is returned, the PSBT is ready to be given to the next signer or
// to be finalized if lnd was the last signer.
//
// NOTE: This RPC only signs inputs (and only those it can sign), it does not
// perform any other tasks (such as coin selection, UTXO locking or
// input/output/fee value validation, PSBT finalization). Any input that is
// incomplete will be skipped.
func (w *walletKit) SignPsbt(ctx context.Context, req *proto.SignPsbtRequest) (
	*proto.SignPsbtResponse, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		signerLog.Debugf("Error parsing PSBT: %v, raw input: %x", err,
			req.FundedPsbt)
		return nil, fmt.Errorf("error parsing PSBT: %v", err)
	}

	// Before we attempt to sign the packet, ensure that every input either
	// has a witness UTXO, or a non witness UTXO.
	for idx := range packet.UnsignedTx.TxIn {
		in := packet.Inputs[idx]

		// Doesn't have either a witness or non witness UTXO so we need
		// to exit here as otherwise signing will fail.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			return nil, fmt.Errorf("input (index=%v) doesn't "+
				"specify any UTXO info", idx)
		}
	}

	// Let the wallet do the heavy lifting. This will sign all inputs that
	// we have the UTXO for. If some inputs can't be signed and don't have
	// witness data attached, they will just be skipped.
	keyRing := ctx.Value(keyRingKey).(*keyring.KeyRing)
	if keyRing == nil {
		return nil, fmt.Errorf("no node/coin from macaroon")
	}

	signedInputs, err := keyRing.SignPsbt(packet)
	if err != nil {
		return nil, fmt.Errorf("error signing PSBT: %v", err)
	}

	// Serialize the signed PSBT in both the packet and wire format.
	var signedPsbtBytes bytes.Buffer
	err = packet.Serialize(&signedPsbtBytes)
	if err != nil {
		return nil, fmt.Errorf("error serializing PSBT: %v", err)
	}

	return &proto.SignPsbtResponse{
		SignedPsbt:   signedPsbtBytes.Bytes(),
		SignedInputs: signedInputs,
	}, nil
}
