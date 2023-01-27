// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hashicorp/vault/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ListenerWithSignal is a net.Listener that has an additional Ready channel
// that will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}
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

	signerLog.Infow("Active Bitcoin network: ", "net",
		cfg.ActiveNetParams.Name)

	// Use defaults for vault client, including getting config from env.
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		return mkErr("error creating vault client: %v", err)
	}

	signerClient := vaultClient.Logical()

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
	rpcServer := newRPCServer(cfg, signerClient)
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

	// The certData returned here is just a wrapper around the PEM blocks
	// loaded from the file. The PEM is not yet fully parsed but a basic
	// check is performed that the certificate and private key actually
	// belong together.
	certData, err := tls.LoadX509KeyPair(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, err
	}

	// Now parse the the PEM block of the certificate.
	_, err = x509.ParseCertificate(certData.Certificate[0])
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certData},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

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
