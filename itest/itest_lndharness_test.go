//go:build itest
// +build itest

package itest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/bottlepay/lndsigner"
	"github.com/bottlepay/lndsigner/itest"
	"io/fs"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// lndHarness manages a single lndsignerd-backed instance of LND.
type lndHarness struct {
	tctx     *testContext
	idPubKey string

	unixSocket bool

	cancel context.CancelFunc

	lndSignerCmd *exec.Cmd

	lndDir    string
	lncliPath string
	rpc       string
	p2p       string
	lndCmd    *exec.Cmd

	startChan chan struct{}
}

// Start takes the initial configuration (tctx, idPubKey, and unixSocket) and
// starts lndsignerd and LND.
func (l *lndHarness) Start() {
	l.tctx.t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel

	// Make a channel. We'll close this channel after the node is fully
	// started to signal clients it's safe to make calls.
	l.startChan = make(chan struct{})

	// Start lndsignerd.
	l.lndDir = path.Join(l.tctx.tmpRoot, fmt.Sprintf("lnd%s", l.idPubKey))
	err := os.Mkdir(l.lndDir, fs.ModeDir|0700)
	require.NoError(l.tctx.t, err)

	keyPath := path.Join(l.lndDir, "signer.key")
	certPath := path.Join(l.lndDir, "signer.cert")

	mustGenCertPair(l.tctx.t, certPath, keyPath)

	macPath := path.Join(l.lndDir, "dummy.macaroon")

	mustGenMacaroon(l.tctx.t, macPath)

	signerAddr := "127.0.0.1:" + newPortString()
	fullSignerAddr := "tcp://" + signerAddr

	if l.unixSocket {
		signerAddr = "unix://" + path.Join(l.tctx.tmpRoot, l.idPubKey+".socket")
		fullSignerAddr = signerAddr
	}

	l.lndSignerCmd = exec.CommandContext(ctx, l.tctx.lndSignerPath,
		"--rpclisten="+fullSignerAddr, "--nodepubkey="+l.idPubKey,
		"--tlscertpath="+certPath, "--tlskeypath="+keyPath,
		"--network=regtest",
	)

	l.lndSignerCmd.Env = append(l.lndSignerCmd.Env,
		"VAULT_ADDR=http://127.0.0.1:"+l.tctx.vaultPort,
		"VAULT_TOKEN=root",
	)

	go waitProc(l.lndSignerCmd)

	// Start lnd.
	acctsResp, err := l.tctx.vaultClient.ReadWithData(
		"lndsigner/lnd-nodes/accounts",
		map[string][]string{
			"node": []string{l.idPubKey},
		},
	)
	require.NoError(l.tctx.t, err)

	acctList, ok := acctsResp.Data["acctList"].(string)
	require.True(l.tctx.t, ok)

	accounts, err := lndsigner.GetAccounts(acctList)
	require.NoError(l.tctx.t, err)

	grpcAccounts := make([]*itest.WatchOnlyAccount, 0,
		len(accounts))

	for derPath, xPub := range accounts {
		grpcAccounts = append(grpcAccounts,
			&itest.WatchOnlyAccount{
				Purpose:  derPath[0],
				CoinType: derPath[1],
				Account:  derPath[2],
				Xpub:     xPub,
			})
	}

	l.rpc = newPortString()
	l.p2p = newPortString()

	l.lndCmd = exec.CommandContext(ctx, l.tctx.lndPath,
		"--lnddir="+l.lndDir, "--norest", "--listen="+l.p2p,
		"--rpclisten="+l.rpc, "--trickledelay=1", "--bitcoin.active",
		"--bitcoin.regtest", "--bitcoin.node=bitcoind",
		"--bitcoind.rpcuser=user", "--bitcoind.rpcpass=password",
		"--bitcoind.rpchost=127.0.0.1:"+l.tctx.bitcoinRPC,
		"--bitcoind.zmqpubrawblock=tcp://"+l.tctx.bitcoinZB.String(),
		"--bitcoind.zmqpubrawtx=tcp://"+l.tctx.bitcoinZT.String(),
		"--remotesigner.enable",
		"--remotesigner.rpchost="+signerAddr,
		"--remotesigner.tlscertpath="+certPath,
		"--remotesigner.macaroonpath="+macPath,
	)

	go waitProc(l.lndCmd)

	go func() {
		// Ensure we wait until lnd has started its wallet unlocker
		// server.
		waitFile(
			l.tctx.t,
			path.Join(l.lndDir, "/logs/bitcoin/regtest/lnd.log"),
			"Waiting for wallet encryption password",
		)

		// Initialize with the accounts information. We use gRPC for this
		// because lncli doesn't run non-interactively, so we have to send a
		// wallet password over gRPC.
		tlsCreds, err := credentials.NewClientTLSFromFile(
			path.Join(l.lndDir, "tls.cert"), "")
		require.NoError(l.tctx.t, err)

		tlsCredsOption := grpc.WithTransportCredentials(tlsCreds)
		unlockerConn, err := grpc.Dial("127.0.0.1:"+l.rpc, tlsCredsOption)
		require.NoError(l.tctx.t, err)

		unlocker := itest.NewWalletUnlockerClient(unlockerConn)
		_, err = unlocker.InitWallet(
			ctx,
			&itest.InitWalletRequest{
				WalletPassword: []byte("weks1234"),
				WatchOnly: &itest.WatchOnly{
					Accounts: grpcAccounts,
				},
			},
		)
		require.NoError(l.tctx.t, err)

		// Wait for lnd to start the main gRPC server. Log file is
		// ~7300 bytes when the RPC server is started.
		// TODO(aakselrod): maybe check log file for
		// "Auto peer bootstrapping" instead?
		waitFile(
			l.tctx.t,
			path.Join(l.lndDir, "/logs/bitcoin/regtest/lnd.log"),
			"Auto peer bootstrapping",
		)

		// Signal any waiting clients that lnd should be initialized
		close(l.startChan)
	}()
}

// Close cleans up LND and lndsignerd.
func (l *lndHarness) Close() {
	l.tctx.t.Helper()

	_ = l.Lncli("stop")
	_ = l.lndSignerCmd.Process.Signal(os.Interrupt)

	l.cancel()
}

// LnCli calls lncli against the harness' LND instance.
func (l *lndHarness) Lncli(args ...string) map[string]interface{} {
	l.tctx.t.Helper()

	<-l.startChan

	lnCliCmd := exec.CommandContext(context.Background(), l.tctx.lncliPath,
		append([]string{"--lnddir=" + l.lndDir,
			"--rpcserver=127.0.0.1:" + l.rpc,
			"--network=regtest",
			"--tlscertpath=./testdata/tls.cert"}, args...)...)

	outBuf := bytes.NewBuffer(make([]byte, 0))
	lnCliCmd.Stdout = outBuf

	errBuf := bytes.NewBuffer(make([]byte, 0))
	lnCliCmd.Stderr = errBuf

	err := lnCliCmd.Start()
	require.NoError(l.tctx.t, err)

	err = lnCliCmd.Wait()
	require.NoError(l.tctx.t, err,
		fmt.Sprintf("lncli (args %+v) failed:\n%s\n%s", args,
			errBuf.Bytes(), outBuf.Bytes()))

	stdout := string(outBuf.Bytes())

	// If we're stopping, we won't get JSON back.
	if args[0] == "stop" {
		return nil
	}

	resp := make(map[string]interface{})
	err = json.Unmarshal([]byte(stdout), &resp)
	require.NoError(l.tctx.t, err)

	return resp
}

// waitFile waits for a log file to contain the requested string.
func waitFile(t *testing.T, file, waitStr string) {
	var (
		err      error
		logBytes []byte
	)

	for {
		time.Sleep(waitDelay)

		logBytes, err = os.ReadFile(file)
		if err != nil {
			require.True(t, os.IsNotExist(err), err)
		}

		if bytes.Contains(logBytes, []byte(waitStr)) {
			break
		}
	}
}

// waitProc launches a goroutine to wait for a long-running program, such as
// vault, bitcoind, lndsignerd, or lnd, to stop. If the program returns an
// exit error, the program's entire stderr and stdout are logged.
func waitProc(cmd *exec.Cmd) {
	output, err := cmd.CombinedOutput()
	if err != nil && err.Error() != "signal: killed" {
		config := zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeCaller = nil
		logger := zap.Must(config.Build()).Sugar()
		logger.Warnw(
			"WARNING: Service exited with error",
			"cmd", cmd.Path,
			"err", err,
			"stdout/stderr", string(output),
		)
	}
}

// newPort finds an open TCP port to listen on.
func newPort() *net.TCPAddr {
	lis, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		panic(err)
	}
	defer lis.Close()
	return lis.Addr().(*net.TCPAddr)
}

// newPortString finds an open TCP port to listen on and returns the port
// number as a string.
func newPortString() string {
	return fmt.Sprintf("%d", newPort().Port)
}

// mustCopyFile copies a file and panics on error.
func mustCopyFile(src, dst string, mode os.FileMode) {
	fileBytes, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dst, fileBytes, mode)
	if err != nil {
		panic(err)
	}
}

func mustGenCertPair(t *testing.T, certFile, keyFile string) {
	now := time.Now()

	// Generate a random serial number.
	serialNumber, err := rand.Int(rand.Reader,
		new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	// Generate a private key for the certificate.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Construct the certificate template.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"test"},
			CommonName:   "localhost",
		},
		NotBefore: now.Add(-time.Hour * 24),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IsCA:                  true, // so can sign self.
		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv6loopback, net.IP{127, 0, 0, 1}},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template,
		&template, &priv.PublicKey, priv,
	)
	require.NoError(t, err)

	certBuf := &bytes.Buffer{}
	require.NoError(t, pem.Encode(
		certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
	))

	keybytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	keyBuf := &bytes.Buffer{}
	require.NoError(t, pem.Encode(
		keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keybytes},
	))

	require.NoError(t, os.WriteFile(certFile, certBuf.Bytes(), 0644))

	require.NoError(t, os.WriteFile(keyFile, keyBuf.Bytes(), 0600))
}

func mustGenMacaroon(t *testing.T, macPath string) {
	var macData []byte

	macData = append(macData, 2)  // version
	macData = append(macData, 1)  // field type loc
	macData = append(macData, 1)  // length
	macData = append(macData, 65) // loc ("A")
	macData = append(macData, 2)  // field type id
	macData = append(macData, 1)  // length
	macData = append(macData, 65) // id ("A")
	macData = append(macData, 0)  // end of seq
	macData = append(macData, 0)  // end of seq
	macData = append(macData, 6)  // field type sig
	macData = append(macData, 32) // length
	macData = append(macData,     // sig (32 * "A")
		65, 65, 65, 65, 65, 65, 65, 65,
		65, 65, 65, 65, 65, 65, 65, 65,
		65, 65, 65, 65, 65, 65, 65, 65,
		65, 65, 65, 65, 65, 65, 65, 65,
	)
	macData = append(macData, 0) // end of seq

	require.NoError(t, os.WriteFile(macPath, macData, 0644))
}
