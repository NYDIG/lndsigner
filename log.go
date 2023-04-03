// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"github.com/nydig/lndsigner/keyring"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var signerLog *zap.SugaredLogger

func init() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeCaller = nil
	rawLog := zap.Must(config.Build())
	signerLog = rawLog.Sugar()
	keyring.UseLogger(signerLog.With(zap.Any("pkg", "keyring")))
}
