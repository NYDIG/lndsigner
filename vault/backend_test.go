package vault

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	filestore "github.com/hashicorp/vault/sdk/physical/file"
	"github.com/stretchr/testify/require"
)

// testContext controls a vault plugin with storage in a temporary directory.
type testContext struct {
	// Basic test context info
	t      *testing.T
	cancel context.CancelFunc

	// tmpDir tracks where we created a temp directory to delete at the end.
	tmpDir string

	// storage tracks the logical storage object for requests.
	storage logical.Storage

	// Plugin back end to test against.
	backEnd *backend
}

// newTestContext creates a new test context from the test environment.
func newTestContext(t *testing.T) *testContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	tmpDir, err := os.MkdirTemp("", "vault-plugin-lndsigner")
	require.NoError(t, err)

	logger := hclog.Default()

	// Create storage in a temp directory. When we use in-memory storage,
	// some request and response data is passed by reference and gets
	// zeroed out inappropriately. This doesn't happen when copies are
	// made by the storage backend.
	pStorage, err := filestore.NewFileBackend(
		map[string]string{"path": tmpDir},
		logger,
	)
	require.NoError(t, err)

	storage := logical.NewLogicalStorage(pStorage)

	b, err := Factory(ctx, &logical.BackendConfig{
		StorageView: storage,
		Logger:      logger,
	})
	require.NoError(t, err)

	return &testContext{
		t:       t,
		cancel:  cancel,
		tmpDir:  tmpDir,
		storage: storage,
		backEnd: b.(*backend),
	}
}

// Close cancels the test context's inner context and deletes the temporary
// directory.
func (tctx *testContext) Close() {
	tctx.t.Helper()

	tctx.cancel()

	require.NoError(tctx.t, os.RemoveAll(tctx.tmpDir))
}

// call sends a request to perform an operation to the plugin backend, and
// returns the response.
func (tctx *testContext) call(path *framework.Path, op logical.Operation,
	data map[string]interface{}) (*logical.Response, error) {

	tctx.t.Helper()

	return path.Operations[op].Handler()(context.Background(),
		&logical.Request{Storage: tctx.storage},
		&framework.FieldData{
			Schema: path.Fields,
			Raw:    data,
		},
	)
}

// update sends an update call to the plugin backend on the specified path, and
// returns the response.
func (tctx *testContext) update(path *framework.Path,
	data map[string]interface{}) (*logical.Response, error) {

	tctx.t.Helper()

	return tctx.call(path, logical.UpdateOperation, data)
}

// read sends a read call to the plugin backend on the specified path, and
// returns the response.
func (tctx *testContext) read(path *framework.Path,
	data map[string]interface{}) (*logical.Response, error) {

	tctx.t.Helper()

	return tctx.call(path, logical.ReadOperation, data)
}

// ecdh calls the ecdh endpoint on the plugin backend, and returns the shared
// key.
func (tctx *testContext) ecdh(data map[string]interface{}) (*logical.Response,
	error) {

	tctx.t.Helper()

	return tctx.update(tctx.backEnd.ecdhPath(), data)
}

// createNode creates a node on the plugin backend with the specified network,
// and returns the node ID.
func (tctx *testContext) createNode(data map[string]interface{}) (
	*logical.Response, error) {

	tctx.t.Helper()

	return tctx.update(tctx.backEnd.basePath(), data)
}

// listNodes lists all of the nodes stored in the plugin backend's storage and
// the network name for each.
func (tctx *testContext) listNodes() (*logical.Response, error) {
	tctx.t.Helper()

	return tctx.read(tctx.backEnd.basePath(), map[string]interface{}{})
}

// derivePubkey requests a pubkey given a node ID and derivation path, and
// returns the derived pubkey.
func (tctx *testContext) derivePubkey(data map[string]interface{}) (
	*logical.Response, error) {

	tctx.t.Helper()

	return tctx.read(tctx.backEnd.signPath(), data)
}

// sign requests a signature given a node ID, derivation path, algorithm,
// optional tweaks, and returns the signature and derived pubkey.
func (tctx *testContext) sign(data map[string]interface{}) (
	*logical.Response, error) {

	tctx.t.Helper()

	return tctx.update(tctx.backEnd.signPath(), data)
}

// TestECDH tests the ECDH endpoint. It's not fully tested because we don't
// have the ability to do deterministic tests without key import.
func TestECDH(t *testing.T) {
	t.Parallel()

	tctx := newTestContext(t)
	defer tctx.Close()

	// Check parsing of peer pubkey.
	_, err := tctx.ecdh(map[string]interface{}{
		"peer": "abcdef",
	})
	require.ErrorIs(t, err, ErrInvalidPeerPubkey)

	// Check parsing of node pubkey.
	_, err = tctx.ecdh(map[string]interface{}{
		"peer": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
		"node": "abcdef",
	})
	require.ErrorIs(t, err, ErrInvalidNodeID)

	// Check that a request for a nonexistent node returns the correct error.
	_, err = tctx.ecdh(map[string]interface{}{
		"peer": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
		"node": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
	})
	require.ErrorIs(t, err, ErrNodeNotFound)

	// Create a node for more ECDH checks.
	resp, err := tctx.createNode(map[string]interface{}{
		"network": "regtest",
	})
	require.NoError(t, err)

	// Get the new node's pubkey.
	createdNode := resp.Data["node"].(string)
	require.Equal(t, 66, len(createdNode))

	// Check that a request for the wrong pubkey returns the correct error.
	_, err = tctx.ecdh(map[string]interface{}{
		"node":   createdNode,
		"pubkey": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25ef",
		"peer":   "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
		"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, ErrPubkeyMismatch)

}

// TestListNodes checks that it's possible to list all of the nodes ever
// created in storage.
func TestListNodes(t *testing.T) {
	t.Parallel()

	tctx := newTestContext(t)
	defer tctx.Close()

	// Check that the node list is empty.
	resp, err := tctx.listNodes()
	require.NoError(t, err)
	require.Equal(t, resp, &logical.Response{
		Data: map[string]interface{}{},
	})

	// Create a node.
	resp, err = tctx.createNode(map[string]interface{}{
		"network": "regtest",
	})
	require.NoError(t, err)

	// Get the new node's pubkey.
	createdNode := resp.Data["node"].(string)
	require.Equal(t, 66, len(createdNode))

	// Check that our new node is in the list.
	resp, err = tctx.listNodes()
	require.NoError(t, err)
	require.Equal(t, resp, &logical.Response{
		Data: map[string]interface{}{
			createdNode: "regtest",
		},
	})
}

// TestDerivePubkey checks that public keys are derived correctly.
func TestDerivePubkey(t *testing.T) {
	t.Parallel()

	tctx := newTestContext(t)
	defer tctx.Close()

	// Create a node.
	resp, err := tctx.createNode(map[string]interface{}{
		"network": "regtest",
	})
	require.NoError(t, err)

	// Get the new node's pubkey.
	createdNode := resp.Data["node"].(string)
	require.Equal(t, 66, len(createdNode))

	// Check that our new node derives its node pubkey correctly.
	resp, err = tctx.derivePubkey(map[string]interface{}{
		"node": createdNode,
		"path": []int{2147484665, 2147483649, 2147483654, 0, 0},
	})
	require.NoError(t, err)
	require.Equal(t, resp, &logical.Response{
		Data: map[string]interface{}{
			"pubkey": createdNode,
		},
	})

	// Check for ErrWrongLengthDerivationPath
	resp, err = tctx.derivePubkey(map[string]interface{}{
		"node": createdNode,
		"path": []int{2147484665, 2147483649, 2147483654, 0, 0, 0},
	})
	require.ErrorIs(t, err, ErrWrongLengthDerivationPath)
	require.Nil(t, resp)

	// Check for ErrNegativeElement
	resp, err = tctx.derivePubkey(map[string]interface{}{
		"node": createdNode,
		"path": []int{-1, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, ErrNegativeElement)
	require.Nil(t, resp)

	// Check for ErrElementOverflow
	resp, err = tctx.derivePubkey(map[string]interface{}{
		"node": createdNode,
		"path": []int{22147484665, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, ErrElementOverflow)
	require.Nil(t, resp)

	// Check for ErrElementNotHardened
	resp, err = tctx.derivePubkey(map[string]interface{}{
		"node": createdNode,
		"path": []int{1017, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, ErrElementNotHardened)
	require.Nil(t, resp)
}

// TestSign checks that the plugin backend signs digests properly. It's not
// yet fully tested because we don't have deterministic tests without key
// import.
func TestSign(t *testing.T) {
	t.Parallel()

	tctx := newTestContext(t)
	defer tctx.Close()

	// Create a node.
	resp, err := tctx.createNode(map[string]interface{}{
		"network": "regtest",
	})
	require.NoError(t, err)

	// Get the new node's pubkey.
	createdNode := resp.Data["node"].(string)
	require.Equal(t, 66, len(createdNode))

	// Check for ErrTooManyTweaks.
	resp, err = tctx.sign(map[string]interface{}{
		"node":     createdNode,
		"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
		"ln1tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"ln2tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"method":   "ecdsa",
		"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, ErrTooManyTweaks)
	require.Nil(t, resp)

	// Check for invalid hex in ln1tweak.
	resp, err = tctx.sign(map[string]interface{}{
		"node":     createdNode,
		"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
		"ln1tweak": "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"method":   "ecdsa",
		"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, hex.InvalidByteError(0x67))
	require.Nil(t, resp)

	// Check for invalid hex in ln2tweak.
	resp, err = tctx.sign(map[string]interface{}{
		"node":     createdNode,
		"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
		"ln2tweak": "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"method":   "ecdsa",
		"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
	})
	require.ErrorIs(t, err, hex.InvalidByteError(0x67))
	require.Nil(t, resp)
}
