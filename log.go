// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"errors"
	"os"

	"github.com/bottlepay/lndsigner/keyring"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btclog"
)

var (
	backend     = btclog.NewBackend(os.Stdout)
	signerLog   = backend.Logger("SIGNER")
	txscriptLog = backend.Logger("TXSCRIPT")
	keyringLog  = backend.Logger("KEYRING")
)

func setLogLevel(level string) error {
	logLevel, ok := btclog.LevelFromString(level)
	if !ok {
		return errors.New("invalid log level: " + level)
	}

	signerLog.SetLevel(logLevel)

	txscriptLog.SetLevel(logLevel)
	txscript.UseLogger(txscriptLog)

	keyringLog.SetLevel(logLevel)
	keyring.UseLogger(keyringLog)

	return nil
}
