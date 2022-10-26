// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/lightningnetwork/lnd/cert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

const (
	// outputFilePermissions is the file permission that is used for
	// creating the signer macaroon file and the accounts list file.
	//
	// Why 640 is safe:
	// Assuming a reasonably secure Linux system, it will have a
	// separate group for each user. E.g. a new user lnd gets assigned group
	// lnd which nothing else belongs to. A system that does not do this is
	// inherently broken already.
	//
	// Since there is no other user in the group, no other user can read
	// admin macaroon unless the administrator explicitly allowed it. Thus
	// there's no harm allowing group read.
	outputFilePermissions = 0640
)

// ListenerWithSignal is a net.Listener that has an additional Ready channel
// that will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}

	// MacChan is an optional way to pass the admin macaroon to the program
	// that started lnd. The channel should be buffered to avoid lnd being
	// blocked on sending to the channel.
	MacChan chan []byte
}

// ListenerCfg is a wrapper around custom listeners that can be passed to lnd
// when calling its main method.
type ListenerCfg struct {
	// RPCListeners can be set to the listeners to use for the RPC server.
	// If empty a regular network listener will be created.
	RPCListeners []*ListenerWithSignal
}

// Main is the true entry point for lnd. It accepts a fully populated and
// validated main configuration struct and an optional listener config struct.
// This function starts all main system components then blocks until a signal
// is received on the shutdownChan at which point everything is shut down again.
func Main(cfg *Config, lisCfg ListenerCfg) error {
	// mkErr makes it easy to return logged errors.
	mkErr := func(format string, args ...interface{}) error {
		signerLog.Errorf("Shutting down because error in main "+
			"method: "+format, args...)
		return fmt.Errorf(format, args...)
	}

	var network string
	switch {
	/*case cfg.MainNet:
	network = "mainnet"
	*/
	case cfg.TestNet3:
		network = "testnet"

	case cfg.SimNet:
		network = "simnet"

	case cfg.RegTest:
		network = "regtest"

	case cfg.SigNet:
		network = "signet"
	}

	signerLog.Infof("Active chain: %v (network=%v)", "bitcoin", network)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Use defaults for vault client, including getting config from env.
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		return mkErr("error creating vault client: %v", err)
	}

	signerClient := vaultClient.Logical()

	nodeListResp, err := signerClient.Read("lndsigner/lnd-nodes")
	if err != nil {
		return mkErr("error getting list of lnd nodes: %v", err)
	}

	// If we're asked to output a watch-only account list, do it here.
	if cfg.OutputAccounts != "" {
		for node := range nodeListResp.Data {
			listAcctsResp, err := signerClient.ReadWithData(
				"lndsigner/lnd-nodes/accounts",
				map[string][]string{
					"node": []string{node},
				},
			)
			if err != nil {
				return mkErr("error listing accounts for "+
					"node %s: %v", node, err)
			}

			acctList, ok := listAcctsResp.Data["acctList"]
			if !ok {
				return mkErr("accounts not returned for "+
					"node %s", node)
			}

			err = os.WriteFile(
				cfg.OutputAccounts+"."+node,
				[]byte(acctList.(string)),
				outputFilePermissions,
			)
			if err != nil {
				return mkErr("error writing account list: %v",
					err)
			}
		}
	}

	// Create a new macaroon service.
	rootKeyStore := &assignedRootKeyStore{
		key: cfg.macRootKey[:],
	}

	// Check that we have a valid caveat, we only accept 3 formats.
	checker := &caveatChecker{}

	bakeryParams := bakery.BakeryParams{
		RootKeyStore: rootKeyStore,
		Location:     "lnd",
		Checker:      checker,
	}

	bkry := bakery.New(bakeryParams)

	// If we're asked to output a macaroon file, do it here.
	if cfg.OutputMacaroon != "" {
		for node, coin := range nodeListResp.Data {
			caveats := []checkers.Caveat{
				checkers.Caveat{
					Condition: checkers.Condition(
						"node",
						node,
					),
				},
				checkers.Caveat{
					Condition: checkers.Condition(
						"coin",
						coin.(json.Number).String(),
					),
				},
			}

			mac, err := bkry.Oven.NewMacaroon(
				ctx,
				bakery.LatestVersion,
				caveats,
				nodePermissions...,
			)
			if err != nil {
				return mkErr("error baking macaroon: %v", err)
			}

			macBytes, err := mac.M().MarshalBinary()
			if err != nil {
				return mkErr("error marshaling macaroon "+
					"binary: %v", err)
			}

			err = os.WriteFile(
				cfg.OutputMacaroon+"."+node,
				macBytes,
				outputFilePermissions,
			)
			if err != nil {
				return mkErr("error writing account list: %v",
					err)
			}
		}
	}

	serverOpts, err := getTLSConfig(cfg)
	if err != nil {
		return mkErr("unable to load TLS credentials: %v", err)
	}

	// If we have chosen to start with a dedicated listener for the
	// rpc server, we set it directly.
	grpcListeners := append([]*ListenerWithSignal{}, lisCfg.RPCListeners...)
	if len(grpcListeners) == 0 {
		// Otherwise we create listeners from the RPCListeners defined
		// in the config.
		for _, grpcEndpoint := range cfg.RPCListeners {
			// Start a gRPC server listening for HTTP/2
			// connections.
			lis, err := ListenOnAddress(grpcEndpoint)
			if err != nil {
				return mkErr("unable to listen on %s: %v",
					grpcEndpoint, err)
			}
			defer lis.Close()

			grpcListeners = append(
				grpcListeners, &ListenerWithSignal{
					Listener: lis,
					Ready:    make(chan struct{}),
				},
			)
		}
	}

	// Initialize the rpcServer and add its interceptor to the server
	// options.
	rpcServer := newRPCServer(cfg, signerClient, bkry.Checker)
	serverOpts = append(
		serverOpts,
		grpc.ChainUnaryInterceptor(rpcServer.intercept),
	)

	// Create the GRPC server with the TLS and interceptor configuration.
	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	// Register our implementation of the gRPC interface exported by the
	// rpcServer.
	err = rpcServer.RegisterWithGrpcServer(grpcServer)
	if err != nil {
		return mkErr("error registering gRPC server: %v", err)
	}

	// Now that both the WalletUnlocker and LightningService have been
	// registered with the GRPC server, we can start listening.
	err = startGrpcListen(cfg, grpcServer, grpcListeners)
	if err != nil {
		return mkErr("error starting gRPC listener: %v", err)
	}

	// Wait for shutdown signal from the interrupt handler.
	signerLog.Infof("Press ctrl-c to exit")

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-sigint

	return nil
}

// getTLSConfig returns a TLS configuration for the gRPC server.
func getTLSConfig(cfg *Config) ([]grpc.ServerOption, error) {

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		signerLog.Infof("Generating TLS certificates...")
		err := cert.GenCertPair(
			"signer autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, err
		}
		signerLog.Infof("Done generating TLS certificates")
	}

	certData, parsedCert, err := cert.LoadCert(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, err
	}

	// We check whether the certificate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.TLSExtraIPs,
			cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		)
		if err != nil {
			return nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		signerLog.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, err
		}

		signerLog.Infof("Renewing TLS certificates...")
		err = cert.GenCertPair(
			"signer autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cfg.TLSCertDuration,
		)
		if err != nil {
			return nil, err
		}
		signerLog.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certData, _, err = cert.LoadCert(
			cfg.TLSCertPath, cfg.TLSKeyPath,
		)
		if err != nil {
			return nil, err
		}
	}

	tlsCfg := cert.TLSConfFromCert(certData)

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	return serverOpts, nil
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// startGrpcListen starts the GRPC server on the passed listeners.
func startGrpcListen(cfg *Config, grpcServer *grpc.Server,
	listeners []*ListenerWithSignal) error {

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *ListenerWithSignal) {
			signerLog.Infof("RPC server listening on %s", lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// Wait for gRPC servers to be up running.
	wg.Wait()

	return nil
}

// parseNetwork parses the network type of the given address.
func parseNetwork(addr net.Addr) string {
	switch addr := addr.(type) {
	// TCP addresses resolved through net.ResolveTCPAddr give a default
	// network of "tcp", so we'll map back the correct network for the given
	// address. This ensures that we can listen on the correct interface
	// (IPv4 vs IPv6).
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return "tcp4"
		}
		return "tcp6"

	default:
		return addr.Network()
	}
}

// ListenOnAddress creates a listener that listens on the given address.
func ListenOnAddress(addr net.Addr) (net.Listener, error) {
	return net.Listen(parseNetwork(addr), addr.String())
}
