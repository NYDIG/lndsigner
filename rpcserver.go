// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"context"
	"fmt"

	"github.com/bottlepay/lndsigner/keyring"
	"github.com/bottlepay/lndsigner/proto"
	"github.com/hashicorp/vault/api"
	"github.com/tv42/zbase32"
	"google.golang.org/grpc"
)

// keyRingKeyStruct is a struct used to look up a keyring passed in a context.
type keyRingKeyStruct struct{}

var (
	keyRingKey = keyRingKeyStruct{}
)

// rpcServer is a gRPC front end to the signer daemon.
type rpcServer struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	// Must be after the atomically used variables to not break struct
	// alignment.
	proto.UnimplementedLightningServer

	client *api.Logical

	cfg *Config

	keyRing *keyring.KeyRing
}

// A compile time check to ensure that rpcServer fully implements the
// LightningServer gRPC service.
var _ proto.LightningServer = (*rpcServer)(nil)

// newRPCServer creates and returns a new instance of the rpcServer. Before
// dependencies are added, this will be an non-functioning RPC server only to
// be used to register the LightningService with the gRPC server.
func newRPCServer(cfg *Config, c *api.Logical) *rpcServer {
	return &rpcServer{
		cfg:    cfg,
		client: c,
		keyRing: keyring.NewKeyRing(
			c,
			cfg.NodePubKey,
			cfg.ActiveNetParams.HDCoinType,
		),
	}
}

// intercept allows the RPC server to intercept requests to ensure that they're
// authorized by a macaroon signed by the macaroon root key.
func (r *rpcServer) intercept(ctx context.Context, req interface{},
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
	interface{}, error) {

	return handler(
		context.WithValue(ctx, keyRingKey, r.keyRing),
		req,
	)
}

// RegisterWithGrpcServer registers the rpcServer and any subservers with the
// root gRPC server.
func (r *rpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	// Register the main RPC server.
	lnDesc := proto.Lightning_ServiceDesc
	lnDesc.ServiceName = "lnrpc.Lightning"
	grpcServer.RegisterService(&lnDesc, r)

	// Register the wallet subserver.
	walletDesc := proto.WalletKit_ServiceDesc
	walletDesc.ServiceName = "walletrpc.WalletKit"
	grpcServer.RegisterService(&walletDesc, &walletKit{
		server: r,
	})

	// Register the signer subserver.
	signerDesc := proto.Signer_ServiceDesc
	signerDesc.ServiceName = "signrpc.Signer"
	grpcServer.RegisterService(&signerDesc, &signerServer{
		server: r,
	})

	return nil
}

var (
	// signedMsgPrefix is a special prefix that we'll prepend to any
	// messages we sign/verify. We do this to ensure that we don't
	// accidentally sign a sighash, or other sensitive material. By
	// prepending this fragment, we mind message signing to our particular
	// context.
	signedMsgPrefix = []byte("Lightning Signed Message:")
)

// SignMessage signs a message with the resident node's private key. The
// returned signature string is zbase32 encoded and pubkey recoverable, meaning
// that only the message digest and signature are needed for verification.
func (r *rpcServer) SignMessage(_ context.Context,
	in *proto.SignMessageRequest) (*proto.SignMessageResponse, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("need a message to sign")
	}

	in.Msg = append(signedMsgPrefix, in.Msg...)
	keyLoc := keyring.KeyLocator{
		Family: 6,
		Index:  0,
	}

	sig, err := r.keyRing.SignMessage(
		keyLoc, in.Msg, !in.SingleHash, true,
	)
	if err != nil {
		return nil, err
	}

	sigStr := zbase32.EncodeToString(sig)
	return &proto.SignMessageResponse{Signature: sigStr}, nil
}
