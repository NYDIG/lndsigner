// Copyright (C) 2022-2023 Bottlepay and The Lightning Network Developers

package keyring

import "errors"

var (
	ErrNoSharedKeyReturned = errors.New("vault returned no shared key")
	ErrBadSharedKey        = errors.New("vault returned bad shared key")
	ErrNoSignatureReturned = errors.New("vault returned no signature")
	ErrNoPubkeyReturned    = errors.New("vault returned no pubkey")
)
