// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nydig/lndsigner/keyring"
	"github.com/nydig/lndsigner/vault"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	idxNotFoundOrDuplicate = 65535
)

type chanInfo struct {
	sync.RWMutex

	ver              byte
	chanPoint        wire.OutPoint
	isInitiator      bool
	remotePub        *btcec.PublicKey
	capacity         uint64
	localCSVDelay    uint16
	remoteCSVDelay   uint16
	localMultisig    keyring.KeyDescriptor
	localRevocation  keyring.KeyDescriptor
	localPayment     keyring.KeyDescriptor
	localDelay       keyring.KeyDescriptor
	localHTLC        keyring.KeyDescriptor
	remoteMultisig   *btcec.PublicKey
	remoteRevocation *btcec.PublicKey
	remotePayment    *btcec.PublicKey
	remoteDelay      *btcec.PublicKey
	remoteHTLC       *btcec.PublicKey
	shaChain         keyring.KeyDescriptor

	// p is the PolicyEngine to which this channel is attached. It lets
	// us query and modify global node state as needed.
	p *PolicyEngine

	// lastSigned tracks the most recent commitment for comparison against
	// the one we're being asked to sign. It should be updated after every
	// channel update. If it's nil, we will accept
	lastSigned *wire.MsgTx

	// ourLastBalance tracks our refund output balance at the last
	// successful commitment signing attempt.
	ourLastBalance uint64
}

// getChanInfo constructs a chanInfo struct from the supplied parameters.
func (p *PolicyEngine) getChanInfo(ctx psbtContext) (*chanInfo, error) {

	chanPoint := ctx.packet.UnsignedTx.TxIn[0].PreviousOutPoint

	p.RLock()
	channel, ok := p.channels[chanPoint]
	p.RUnlock()

	if ok {
		return channel, nil
	}

	acctKey, ok := p.accounts[[3]uint32{
		vault.Bip0043purpose + hdkeychain.HardenedKeyStart, // LND.
		p.coin + hdkeychain.HardenedKeyStart,               // Coin type.
		7 + hdkeychain.HardenedKeyStart,                    // Encryption.
	}]
	if !ok {
		return nil, fmt.Errorf("couldn't get encryption base key: %+v: %+v",
			p.coin, p.accounts)
	}

	// We do these derivations with DeriveNonStandard to match btcwallet's
	// (and thus lnd's) usage as shown here:
	// https://github.com/btcsuite/btcwallet/blob/c314de6995500686c93716037f2279128cc1e9e8/waddrmgr/manager.go#L1459
	branchKey, err := acctKey.DeriveNonStandard( // nolint:staticcheck
		0, // Always external.
	)
	if err != nil {
		return nil, err
	}

	idxKey, err := branchKey.DeriveNonStandard( // nolint:staticcheck
		0, // Always 0 for now.
	)
	if err != nil {
		return nil, err
	}

	ecBaseKey, err := idxKey.ECPubKey()
	if err != nil {
		return nil, err
	}

	encKey := sha256.Sum256(ecBaseKey.SerializeCompressed())

	// Read node's channel backup file. We add a suffix for the specific
	// node, just as we do when writing a macaroon or accounts file.
	// We expect that this is updated every time a new channel is opened.
	// This makes it easy to use a symlink in local testing, but requires
	// production deployments to somehow get the backup file to the signer
	// after each channel opening.
	//
	// TODO(aakselrod): better integration here.
	backup, err := os.ReadFile(p.chanBackup)
	if err != nil {
		return nil, err
	}

	channels, err := getChannelsFromBackup(encKey[:], backup)
	if err != nil {
		return nil, err
	}

	for _, channel = range channels {
		if channel.chanPoint == chanPoint {
			// Derive pubkeys and populate field in descriptors.
			toDerive := []*keyring.KeyDescriptor{
				&channel.localMultisig,
				&channel.localRevocation,
				&channel.localPayment,
				&channel.localDelay,
				&channel.localHTLC,
			}

			if channel.shaChain.PubKey == nil {
				toDerive = append(toDerive, &channel.shaChain)
			}

			for _, el := range toDerive {
				actKey, ok := p.accounts[[3]uint32{
					1017 + hdkeychain.HardenedKeyStart,
					p.coin + hdkeychain.HardenedKeyStart,
					el.Family + hdkeychain.HardenedKeyStart,
				}]

				if !ok {
					return nil, fmt.Errorf("invalid " +
						"account in channel backup")
				}

				// We do these derivations with
				// DeriveNonStandard to match btcwallet's (and
				// thus lnd's) usage as shown here:
				// https://github.com/btcsuite/btcwallet/blob/c314de6995500686c93716037f2279128cc1e9e8/waddrmgr/manager.go#L1459
				branchKey, err := actKey.DeriveNonStandard( // nolint:staticcheck
					0,
				)
				if err != nil {
					return nil, err
				}

				idxKey, err := branchKey.DeriveNonStandard( // nolint:staticcheck
					el.Index,
				)
				if err != nil {
					return nil, err
				}

				el.PubKey, err = idxKey.ECPubKey()
				if err != nil {
					return nil, err
				}
			}

			// Cache channel state.
			channel.p = p
			p.Lock()
			p.channels[chanPoint] = channel
			p.Unlock()

			return channel, nil
		}
	}

	return nil, nil
}

func (c *chanInfo) enforcePolicy(ctx psbtContext) (interface{}, error) {

	logger := log.With("chan", c.chanPoint)

	logger.Debug("Enforcing channel policy")

	// See if this is a commit owned by the remote party.
	ourScript, err := c.ourScriptForCommit()
	if err != nil {
		return nil, err
	}

	if ourScript == nil {
		// TODO(aakselrod): handle this.
		return ctx.handler(ctx, ctx.req)
	}

	tx := ctx.packet.UnsignedTx

	ourIdx := findMatchingOutputScript(tx, ourScript)
	if ourIdx == idxNotFoundOrDuplicate {
		// TODO(aakselrod): handle this.
		logger.Warn("No output script matches our remote commit script")
		return ctx.handler(ctx, ctx.req)
	}

	value := uint64(tx.TxOut[ourIdx].Value)

	logger.Debugw("Found our output", "idx", ourIdx, "value", value)

	c.Lock()
	defer c.Unlock()

	// TODO(aakselrod): Get initial balance in here somehow before we're
	// asked to sign a change to it.
	if c.lastSigned == nil {
		resp, err := ctx.handler(ctx, ctx.req)
		if err != nil {
			return nil, err
		}

		logger.Debug("Populating initial channel balance")

		c.lastSigned = tx
		c.ourLastBalance = value

		c.p.Lock()
		defer c.p.Unlock()

		c.p.channelBalance += value
		c.p.lastSpend = time.Now()
		return resp, nil
	}

	c.p.Lock()
	defer c.p.Unlock()

	// If we're not reducing our balance, only update the balance and last
	// signed TX. We aren't going to use the current time to calculate
	// spend rate because this isn't a new spend.
	if value >= c.ourLastBalance {
		resp, err := ctx.handler(ctx, ctx.req)
		if err != nil {
			return nil, err
		}

		c.p.channelBalance += (value - c.ourLastBalance)
		c.ourLastBalance = value
		c.lastSigned = tx
		return resp, nil
	}

	// Here we calculate the average spend rate created by this payment
	// since the last payment.
	//
	// TODO(aakselrod): find a better rate limiting algorithm to use here.
	// This one can be monopolized by many small frequent payments,
	// disallowing larger payments. It also breaks routing, because when
	// the node gets an incoming HTLC on a channel it initiated, it needs
	// to decrease its balance to reserve more TX fees for the increased
	// commit TX size. This looks like a spend to this algorithm.
	now := time.Now()
	rate := (int64(c.ourLastBalance) - int64(value)) * 1e9 /
		int64(now.Sub(c.p.lastSpend))
	if rate > MaxSpendRate {
		return nil, fmt.Errorf("Spending too fast at %d sats/sec "+
			"(max %d)", rate, MaxSpendRate)
	}

	logger.Debugw("Allowing channel spend", "spend_rate", rate)

	resp, err := ctx.handler(ctx, ctx.req)
	if err != nil {
		return nil, err
	}

	c.p.lastSpend = now
	c.p.channelBalance -= (c.ourLastBalance - value)
	c.ourLastBalance = value
	c.lastSigned = tx

	return resp, nil
}

func (c *chanInfo) ourScriptForCommit() ([]byte, error) {
	switch c.ver {
	case 3:
		builder := txscript.NewScriptBuilder()

		// Only the given key can spend the output.
		builder.AddData(c.localPayment.PubKey.SerializeCompressed())
		builder.AddOp(txscript.OP_CHECKSIGVERIFY)

		// Check that the it has one confirmation.
		builder.AddOp(txscript.OP_1)
		builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)

		script, err := builder.Script()
		if err != nil {
			return nil, err
		}

		return witnessScriptHash(script)

	default:
		return nil, fmt.Errorf("unsupported channel version: %d", c.ver)
	}
}

func getChannelsFromBackup(encKey, backup []byte) ([]*chanInfo, error) {

	if len(backup) < 45 { // chanbckup.NilMultiSizePacked
		return nil, fmt.Errorf("encrypted channel backup too short")
	}

	nonce := backup[:chacha20poly1305.NonceSizeX]
	ciphertext := backup[chacha20poly1305.NonceSizeX:]

	cipher, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return nil, err
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, nonce)
	if err != nil {
		return nil, err
	}

	if len(plaintext) < 5 {
		return nil, fmt.Errorf("channel backup plaintext too short")
	}

	buf := bytes.NewBuffer(plaintext)

	var mVer byte
	err = readElement(buf, &mVer)
	if err != nil {
		return nil, err
	}

	if mVer != byte(0) { // Only default multi-backup version allowed.
		return nil, fmt.Errorf("invalid multi-channel backup version")
	}

	var numChans uint32
	err = readElement(buf, &numChans)
	if err != nil {
		return nil, err
	}

	channels := make([]*chanInfo, numChans)
	for idx := uint32(0); idx < numChans; idx++ {
		channel := &chanInfo{}
		channels[idx] = channel

		err = readElement(buf, &channel.ver)
		if err != nil {
			return nil, err
		}

		// Check that version is known.
		if channel.ver > byte(4) {
			return nil, fmt.Errorf("invalid channel backup version")
		}

		var addrByteLength uint16
		dummy := make([]byte, 33)

		err = readElements(
			buf,
			dummy[:2], // Length.
			&channel.isInitiator,
			dummy[:32], // Chain hash.
			&channel.chanPoint,
			dummy[:8], // SCID.
			&channel.remotePub,
			&addrByteLength,
		)
		if err != nil {
			return nil, err
		}

		// Skip the address bytes.
		for i := uint16(0); i < addrByteLength; i++ {
			_, err = buf.ReadByte()
			if err != nil {
				return nil, err
			}
		}

		err = readElements(
			buf,
			&channel.capacity,
			&channel.localCSVDelay,
		)
		if err != nil {
			return nil, err
		}

		for _, el := range []*keyring.KeyDescriptor{
			&channel.localMultisig,
			&channel.localRevocation,
			&channel.localPayment,
			&channel.localDelay,
			&channel.localHTLC,
		} {
			var desc keyring.KeyDescriptor
			err = readElements(buf, &desc.Family, &desc.Index)
			if err != nil {
				return nil, err
			}

			*el = desc
		}

		channel.shaChain = keyring.KeyDescriptor{}

		err = readElements(
			buf,
			&channel.remoteCSVDelay,
			&channel.remoteMultisig,
			&channel.remoteRevocation,
			&channel.remotePayment,
			&channel.remoteDelay,
			&channel.remoteHTLC,
			&channel.shaChain.PubKey,
			&channel.shaChain.Family,
			&channel.shaChain.Index,
		)
		if err != nil {
			return nil, err
		}

		// Continue if we don't need to read the channel lease expiry.
		if channel.ver != 4 {
			continue
		}

		// Lease expiry.
		err = readElement(buf, dummy[:4])
		if err != nil {
			return nil, err
		}
	}

	return channels, nil
}

func readElements(buf io.Reader, elements ...interface{}) error {
	var err error

	for _, el := range elements {
		err = readElement(buf, el)
		if err != nil {
			return err
		}
	}

	return nil
}

func readElement(buf io.Reader, element interface{}) error {
	var err error

	switch el := element.(type) {
	case **btcec.PublicKey:
		var b, z [33]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		if bytes.Equal(b[:], z[:]) {
			break
		}

		*el, err = btcec.ParsePubKey(b[:])

	case *wire.OutPoint:
		var out wire.OutPoint

		err = readElement(buf, out.Hash[:])
		if err != nil {
			break
		}

		var idx uint16
		err = readElement(buf, &idx)
		if err != nil {
			break
		}

		out.Index = uint32(idx)
		*el = out

	case *byte:
		var b [1]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		*el = b[0]

	case *uint64:
		var b [8]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		*el = binary.BigEndian.Uint64(b[:])

	case *uint32:
		var b [4]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		*el = binary.BigEndian.Uint32(b[:])

	case *uint16:
		var b [2]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		*el = binary.BigEndian.Uint16(b[:])

	case []byte:
		_, err = io.ReadFull(buf, el[:])

	case *bool:
		var b [1]byte
		_, err = io.ReadFull(buf, b[:])
		if err != nil {
			break
		}

		*el = false
		if b[0] == 1 {
			*el = true
		}

	default:
		err = fmt.Errorf("unknown element type")
	}

	return err
}

// witnessScriptHash generates a pay-to-witness-script-hash public key script
// paying to a version 0 witness program paying to the passed redeem script.
func witnessScriptHash(witnessScript []byte) ([]byte, error) {
	bldr := txscript.NewScriptBuilder()

	bldr.AddOp(txscript.OP_0)
	scriptHash := sha256.Sum256(witnessScript)
	bldr.AddData(scriptHash[:])
	return bldr.Script()
}

// This function will return 65535 (max uint16 value) if the script is not
// found or appears in more than one output.
func findMatchingOutputScript(tx *wire.MsgTx, script []byte) uint16 {
	idx := uint16(idxNotFoundOrDuplicate)

	for i, txo := range tx.TxOut {
		if !bytes.Equal(txo.PkScript, script) {
			continue
		}

		// Do we have a duplicate match?
		if idx != idxNotFoundOrDuplicate {
			return idxNotFoundOrDuplicate
		}

		idx = uint16(i)
	}

	return idx
}
