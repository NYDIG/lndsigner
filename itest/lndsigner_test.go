//go:build itest
// +build itest

package itest_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	lndCreatePath = "lndsigner/lnd-nodes"
	lndImportPath = "lndsigner/lnd-nodes/import"

	mineDelay = 500 * time.Millisecond
	waitDelay = 100 * time.Millisecond
)

// TestIntegration function runs end-to-end tests using all of the required
// binaries.
//
// This assumes we've got `lnd`, `lncli`, `vault`, `bitcoind`, `bitcoin-cli`,
// and the binaries produced by this package installed and available in the
// executable path. These are installed in CI by the GitHub workflow, but
// for now need to be installed manually in the dev environment.
//
// TODO(aakselrod): add Dockerfile to dockerize itests locally.
func TestIntegration(t *testing.T) {
	tctx := newTestContext(t)
	defer tctx.Close()

	// Create a randomly-initialized node for which nobody's ever seen the
	// keys.

	_ = tctx.addNode(lndCreatePath, map[string]interface{}{
		"network": "regtest",
	}, true)

	// Import node without passphrase.
	lnd2PK := "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6"
	require.Equal(t, tctx.addNode(lndImportPath, map[string]interface{}{
		"network":    "regtest",
		"seedphrase": "absent walnut slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall guard",
		"passphrase": "",
		"node":       lnd2PK,
	}, true), lnd2PK)

	// Import node with passphrase.
	lnd3PK := "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf"
	require.Equal(t, tctx.addNode(lndImportPath, map[string]interface{}{
		"network":    "testnet",
		"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
		"passphrase": "weks1234",
		"node":       lnd3PK,
	}, false), lnd3PK)

	tctx.waitForSync()

	t.Run("fund each lnd with a p2tr address", tctx.testFundLnds)

	tctx.mine(1)
	tctx.waitForSync()

	t.Run("sweep p2tr to p2wkh address", tctx.testSweepToP2WKH)

	tctx.mine(1)
	tctx.waitForSync()

	t.Run("sweep p2wkh to np2wkh address", tctx.testSweepToNP2WKH)

	tctx.mine(1)
	tctx.waitForSync()

	t.Run("sweep np2wkh to p2tr address", tctx.testSweepToP2TR)

	tctx.mine(1)
	tctx.waitForSync()

	t.Run("open channel lnd1 to lnd2", func(t *testing.T) {
		_ = tctx.lnds[0].Lncli("connect",
			tctx.lnds[1].idPubKey+"@127.0.0.1:"+tctx.lnds[1].p2p)

		resp := tctx.lnds[0].Lncli("openchannel", tctx.lnds[1].idPubKey,
			"10000000", "5000000")
		require.Equal(t, 64, len(resp["funding_txid"].(string)))
	})

	t.Run("open channel lnd2 to lnd3", func(t *testing.T) {
		_ = tctx.lnds[1].Lncli("connect",
			tctx.lnds[2].idPubKey+"@127.0.0.1:"+tctx.lnds[2].p2p)

		resp := tctx.lnds[1].Lncli("openchannel", tctx.lnds[2].idPubKey,
			"10000000", "5000000")
		require.Equal(t, 64, len(resp["funding_txid"].(string)))
	})

	// Confirm our channels.
	tctx.mine(5)
	tctx.waitForSync()
	tctx.mine(5)
	tctx.waitForSync()
	tctx.waitForGraphSync()

	t.Run("sign and verify messages", tctx.testEachSignVerifyEachOther)

	t.Run("each lnd pays every other lnd", tctx.testEachPaysEachOther)
}

// testFundLnds funds each lnd instance in the test context with 1 BTC into
// a new P2TR address.
func (tctx *testContext) testFundLnds(t *testing.T) {
	tctx.testEach(func(lnd *lndHarness) {
		resp := lnd.Lncli("newaddress", "p2tr")
		address := resp["address"].(string)

		tctx.bitcoinCli("-named", "sendtoaddress",
			"address="+address, "amount=1", "fee_rate=25")
	})
}

// testSweepToP2WKH sweeps all of the nodes' on-chain funds into P2WKH
// addresses
func (tctx *testContext) testSweepToP2WKH(t *testing.T) {
	tctx.testEach(func(lnd *lndHarness) {
		resp := lnd.Lncli("newaddress", "p2wkh")
		address := resp["address"].(string)

		resp = lnd.Lncli("sendcoins", "--sweepall",
			address)
		require.Equal(t, 64, len(resp["txid"].(string)))

		tctx.log.Infow("swept", "node", lnd.idPubKey)
	})
}

// testSweepToNP2WKH sweeps all of the nodes' on-chain funds into NP2WKH
// addresses
func (tctx *testContext) testSweepToNP2WKH(t *testing.T) {
	tctx.testEach(func(lnd *lndHarness) {
		resp := lnd.Lncli("newaddress", "np2wkh")
		address := resp["address"].(string)

		resp = lnd.Lncli("sendcoins", "--sweepall",
			address)
		require.Equal(t, 64, len(resp["txid"].(string)))

		tctx.log.Infow("swept", "node", lnd.idPubKey)
	})
}

// testSweepToP2TR sweeps all of the nodes' on-chain funds into P2TR
// addresses
func (tctx *testContext) testSweepToP2TR(t *testing.T) {
	tctx.testEach(func(lnd *lndHarness) {
		resp := lnd.Lncli("newaddress", "p2tr")
		address := resp["address"].(string)

		resp = lnd.Lncli("sendcoins", "--sweepall",
			address)
		require.Equal(t, 64, len(resp["txid"].(string)))

		tctx.log.Infow("swept", "node", lnd.idPubKey)
	})
}

// testEachPaysEachOther sends LN payments from each LND to each other LND,
// testing both direct and chained payments.
func (tctx *testContext) testEachPaysEachOther(t *testing.T) {
	tctx.testEachPair(func(lnd1, lnd2 *lndHarness) {
		resp := lnd1.Lncli("addinvoice", "5000")
		invoice := resp["payment_request"].(string)

		resp = lnd2.Lncli("payinvoice", "--timeout=10s", "--json",
			"-f", invoice)
		require.Equal(t, resp["status"].(string), "SUCCEEDED")

		tctx.log.Infow("payment", "src", lnd2.idPubKey,
			"dst", lnd1.idPubKey)
	})
}

// testEachSignVerifyEachOther signs a message from each LND to each other LND,
// verifying the message on the second LND.
func (tctx *testContext) testEachSignVerifyEachOther(t *testing.T) {
	tctx.testEachPair(func(lnd1, lnd2 *lndHarness) {
		message := lnd1.idPubKey + " to " + lnd2.idPubKey

		resp := lnd1.Lncli("signmessage", message)
		sig := resp["signature"].(string)

		resp = lnd2.Lncli("verifymessage", message, sig)
		require.True(t, resp["valid"].(bool))

		tctx.log.Info(message)
	})
}
