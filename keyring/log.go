// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package keyring

import (
	"go.uber.org/zap"
)

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var log *zap.SugaredLogger = zap.NewNop().Sugar()

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger *zap.SugaredLogger) {
	log = logger
}
