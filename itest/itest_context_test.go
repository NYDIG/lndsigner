//go:build itest
// +build itest

package itest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// testContext manages the test environment.
type testContext struct {
	t      *testing.T
	log    *zap.SugaredLogger
	cancel context.CancelFunc

	tmpRoot string

	vaultPort   string
	vaultCmd    *exec.Cmd
	vaultClient *api.Logical

	bitcoinDir     string
	bitcoinRPC     string
	bitcoinZB      *net.TCPAddr
	bitcoinZT      *net.TCPAddr
	bitcoindCmd    *exec.Cmd
	bitcoindClient *api.Logical
	blocksMined    uint32

	lndPath        string
	lndSignerPath  string
	lncliPath      string
	bitcoincliPath string

	lnds []*lndHarness
}

//newTestContext creates a new test context.
func newTestContext(t *testing.T) *testContext {
	t.Helper()

	tctx := &testContext{
		t:    t,
		log:  zaptest.NewLogger(t).Sugar(),
		lnds: make([]*lndHarness, 0, 3),
	}

	ctx, cancel := context.WithCancel(context.Background())
	tctx.cancel = cancel

	// Create temp directory for test context.
	tmpRoot, err := os.MkdirTemp("", "lndsigner-itest")
	require.NoError(t, err)
	tctx.tmpRoot = tmpRoot

	// Get binary paths
	bitcoindPath, err := exec.LookPath("bitcoind")
	require.NoError(t, err)

	tctx.lndPath, err = exec.LookPath("lnd")
	require.NoError(tctx.t, err)

	tctx.lndSignerPath, err = exec.LookPath("lndsignerd")
	require.NoError(tctx.t, err)

	tctx.lncliPath, err = exec.LookPath("lncli")
	require.NoError(tctx.t, err)

	tctx.bitcoincliPath, err = exec.LookPath("bitcoin-cli")
	require.NoError(tctx.t, err)

	// Start bitcoind
	tctx.bitcoinDir = path.Join(tctx.tmpRoot, "bitcoin")
	err = os.Mkdir(tctx.bitcoinDir, fs.ModeDir|0700)
	require.NoError(t, err)

	tctx.bitcoinRPC = newPortString()
	tctx.bitcoinZB = newPort()
	tctx.bitcoinZT = newPort()

	tctx.bitcoindCmd = exec.CommandContext(ctx, bitcoindPath, "-server=1",
		"-datadir="+tctx.bitcoinDir, "-listen=0", "-txindex=1",
		"-regtest=1", "-rpcuser=user", "-rpcpassword=password",
		"-rpcport="+tctx.bitcoinRPC,
		"-zmqpubrawblock=tcp://"+tctx.bitcoinZB.String(),
		"-zmqpubrawtx=tcp://"+tctx.bitcoinZT.String())

	go waitProc(tctx.bitcoindCmd)

	// Wait for bitcoind to start. Log file is ~6300 bytes when regtest
	// bitcoind with our options is started.
	waitFile(
		t,
		path.Join(tctx.bitcoinDir, "/regtest/debug.log"),
		"init message: Done loading",
	)

	// Mine blocks to give us funds and activate soft forks.
	go func() {
		tctx.bitcoinCli("createwallet", "default")
		tctx.mine(1000)
	}()

	// Start vault.
	vaultPath, err := exec.LookPath("vault")
	require.NoError(t, err)

	pluginPath, err := exec.LookPath("vault-plugin-lndsigner")
	require.NoError(t, err)

	pluginDir := path.Join(tmpRoot, "vault_plugins")
	err = os.Mkdir(pluginDir, fs.ModeDir|0700)
	require.NoError(t, err)

	mustCopyFile(pluginPath, path.Join(pluginDir, "vault-plugin-lndsigner"),
		0700)

	tctx.vaultPort = newPortString()
	tctx.vaultCmd = exec.CommandContext(ctx, vaultPath, "server", "-dev",
		"-dev-root-token-id=root", "-dev-plugin-dir="+pluginDir,
		"-dev-listen-address=127.0.0.1:"+tctx.vaultPort)

	go waitProc(tctx.vaultCmd)

	vaultClientConf := api.DefaultConfig()
	vaultClientConf.Address = "http://127.0.0.1:" + tctx.vaultPort

	vaultClient, err := api.NewClient(vaultClientConf)
	require.NoError(t, err)

	vaultClient.SetToken("root")

	tctx.vaultClient = vaultClient.Logical()

	vaultSys := vaultClient.Sys()
	err = vaultSys.Mount("lndsigner", &api.MountInput{
		Type: "vault-plugin-lndsigner",
	})
	require.NoError(t, err)

	return tctx
}

// bitcoinCli sends a command to the test context's bitcoind.
func (tctx *testContext) bitcoinCli(args ...string) map[string]interface{} {
	tctx.t.Helper()

	bitcoinCliCmd := exec.CommandContext(context.Background(),
		tctx.bitcoincliPath,
		append([]string{"-datadir=" + tctx.bitcoinDir,
			"-rpcport=" + tctx.bitcoinRPC, "-rpcuser=user",
			"-rpcpassword=password", "-rpcwaittimeout=5"},
			args...)...)

	stdErrBuf := bytes.NewBuffer(make([]byte, 0))
	bitcoinCliCmd.Stderr = stdErrBuf

	stdOutBuf := bytes.NewBuffer(make([]byte, 0))
	bitcoinCliCmd.Stdout = stdOutBuf

	err := bitcoinCliCmd.Start()
	require.NoError(tctx.t, err)

	// If there's an error on exit, show stderr.
	err = bitcoinCliCmd.Wait()
	require.NoError(tctx.t, err, string(stdErrBuf.Bytes()))

	stdout := string(stdOutBuf.Bytes())

	// sendtoaddress only returns a txid on success. In this case, the
	// first argument is "-named".
	if len(args) > 1 && args[1] == "sendtoaddress" {
		return map[string]interface{}{
			"txid": stdout[:64],
		}
	}

	// If we're stopping, we won't get JSON back.
	if args[0] == "stop" {
		return nil
	}

	// If there's an error parsing the JSON, show stdout to see the issue.
	resp := make(map[string]interface{})
	err = json.Unmarshal([]byte(stdout), &resp)
	require.NoError(tctx.t, err, stdout)

	return resp
}

// Close cleans up the test context.
func (tctx *testContext) Close() {
	tctx.t.Helper()

	for _, lnd := range tctx.lnds {
		lnd.Close()
	}

	_ = tctx.bitcoinCli("stop")
	_ = tctx.vaultCmd.Process.Signal(os.Interrupt)

	tctx.cancel()

	os.RemoveAll(tctx.tmpRoot)
}

// addNode adds a new LND node to the test context, complete with its own
// lndsignerd. reqPath can be used to specify create or import, reqData must
// have a network and optional seed/passphrase, and unixSocket may be used to
// specify that a UNIX socket should be used to communicate between LND and
// lndsignerd.
func (tctx *testContext) addNode(reqPath string,
	reqData map[string]interface{}, unixSocket bool) string {

	tctx.t.Helper()

	resp, err := tctx.vaultClient.Write(reqPath, reqData)
	require.NoError(tctx.t, err)

	pubKey, ok := resp.Data["node"].(string)
	require.True(tctx.t, ok)
	require.Equal(tctx.t, 66, len(pubKey))

	lnd := &lndHarness{
		tctx:       tctx,
		idPubKey:   pubKey,
		unixSocket: unixSocket,
	}

	lnd.Start()

	tctx.lnds = append(tctx.lnds, lnd)

	return pubKey
}

// mine mines the specified number of blocks, and ensures `getblockchaininfo`
// returns the correct number.
func (tctx *testContext) mine(blocks int) {
	tctx.t.Helper()

	// Ensure all TXs are accepted to mempool.
	time.Sleep(mineDelay)

	require.Equal(tctx.t, blocks,
		len(tctx.bitcoinCli("-generate", fmt.Sprintf(
			"%d", blocks))["blocks"].([]interface{})))

	reqMined := int(atomic.AddUint32(&tctx.blocksMined, uint32(blocks)))

	var (
		mined int
		resp  map[string]interface{}
	)

	for mined < reqMined || mined < 1000 {
		time.Sleep(waitDelay)

		resp = tctx.bitcoinCli("getblockchaininfo")
		mined = int(resp["blocks"].(float64))
	}
}

// waitForSync ensures that each LND has caught up to the blocks that have been
// mined on bitcoind.
func (tctx *testContext) waitForSync() {
	tctx.t.Helper()

	// Ensure everyone has time to catch up.
	time.Sleep(mineDelay)

	blocks := int(atomic.LoadUint32(&tctx.blocksMined))

	var resp map[string]interface{}
	for _, lnd := range tctx.lnds {
		synced := 0

		for synced != blocks {
			time.Sleep(waitDelay)

			resp = lnd.Lncli("getinfo")
			require.Equal(tctx.t, resp["identity_pubkey"].(string),
				lnd.idPubKey)

			synced = int(resp["block_height"].(float64))
		}
	}
}

// waitForGraphSync ensures that each LND has a synchronized graph.
func (tctx *testContext) waitForGraphSync() {
	tctx.t.Helper()

	var (
		nodes, chans int
		synced       bool
		resp         map[string]interface{}
	)

	for !synced {
		synced = true

		for _, lnd := range tctx.lnds {

			resp = lnd.Lncli("getnetworkinfo")

			gotNodes := int(resp["num_nodes"].(float64))
			if gotNodes != nodes {
				synced = false

				if gotNodes > nodes {
					nodes = gotNodes
				}
			}

			gotChans := int(resp["num_channels"].(float64))
			if gotChans != chans {
				synced = false

				if gotChans > chans {
					chans = gotChans
				}
			}
		}

		time.Sleep(mineDelay)
	}

	// One final round of `describegraph` to ensure we've updated our
	// routing information.
	for _, lnd := range tctx.lnds {
		lnd.Lncli("describegraph")
	}
}

// testEach runs a function for each LND instance, in parallel.
func (tctx *testContext) testEach(test func(lnd *lndHarness)) {
	tctx.t.Helper()

	var wg sync.WaitGroup
	for _, lnd := range tctx.lnds {
		innerLnd := lnd

		wg.Add(1)
		go func() {
			defer wg.Done()

			test(innerLnd)
		}()
	}

	wg.Wait()
}

// testEachPair runs a function for each pair of LNDs in parallel, avoiding
// testing an LND instance with itself.
func (tctx *testContext) testEachPair(test func(lnd1, lnd2 *lndHarness)) {
	tctx.t.Helper()

	var wg sync.WaitGroup
	for i, lnd1 := range tctx.lnds {
		for j, lnd2 := range tctx.lnds {
			innerLnd1 := lnd1
			innerLnd2 := lnd2

			if i == j {
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()

				test(innerLnd1, innerLnd2)
			}()
		}
	}

	wg.Wait()
}
