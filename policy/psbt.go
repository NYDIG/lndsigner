package policy

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/davecgh/go-spew/spew"
	"github.com/nydig/lndsigner/proto"
	"github.com/nydig/lndsigner/vault"
	"google.golang.org/grpc"
)

type psbtContext struct {
	context.Context

	req *proto.SignPsbtRequest

	handler grpc.UnaryHandler

	packet *psbt.Packet
}

func (p *PolicyEngine) enforcePsbt(ctx context.Context,
	req *proto.SignPsbtRequest, handler grpc.UnaryHandler) (
	interface{}, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		log.Debugw("Error parsing PSBT", "err", err,
			"psbt", req.FundedPsbt)
		return nil, fmt.Errorf("error parsing PSBT: %v", err)
	}

	log.Debugf("Got PSBT packet to sign with unsigned TX: \n%s\nPOutputs: %s",
		spew.Sdump(packet.UnsignedTx), spew.Sdump(packet.Outputs))

	callCtx := psbtContext{
		ctx,
		req,
		handler,
		packet,
	}

	if len(packet.UnsignedTx.TxIn) != 1 || len(packet.Inputs) != 1 {
		// Single input for channel update should be channel point, so
		// this must be an on-chain spend.
		return p.enforceOnChainPolicy(callCtx)
	}

	derPaths := packet.Inputs[0].Bip32Derivation
	if len(derPaths) != 1 {
		// We expect exactly one derivation path for a channel update.
		return p.enforceOnChainPolicy(callCtx)
	}

	derPath := derPaths[0].Bip32Path

	if len(derPath) != 5 {
		return nil,
			fmt.Errorf("invalid derivation path in PSBT request")
	}

	if derPath[0] != vault.Bip0043purpose+ // Channel update for LN.
		hdkeychain.HardenedKeyStart ||
		derPath[1] != p.coin+ // Coin type must match.
			hdkeychain.HardenedKeyStart ||
		derPath[2] != hdkeychain.HardenedKeyStart { // Multisig.

		// Not deriving from the correct account to sign for a
		// channel point.
		return p.enforceOnChainPolicy(callCtx)
	}

	channel, err := p.getChanInfo(callCtx)
	if err != nil {
		return nil, err
	}

	if channel == nil {
		return p.enforceOnChainPolicy(callCtx)
	}

	return channel.enforcePolicy(callCtx)
}

func (p *PolicyEngine) enforceOnChainPolicy(ctx psbtContext) (
	interface{}, error) {

	// TODO(aakselrod): Handle on-chain policy enforcement.
	log.Debug("Enforcing on-chain policy for PSBT")

	return ctx.handler(ctx, ctx.req)
}
