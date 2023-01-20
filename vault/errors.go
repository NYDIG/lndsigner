package vault

import (
	"errors"
)

var (
	ErrInvalidPeerPubkey         = errors.New("invalid peer pubkey")
	ErrInvalidNodeID             = errors.New("invalid node id")
	ErrNodeNotFound              = errors.New("node not found")
	ErrInvalidSeedFromStorage    = errors.New("invalid seed from storage")
	ErrElementNotHardened        = errors.New("derivation path element not hardened")
	ErrNegativeElement           = errors.New("negative derivation path element")
	ErrWrongLengthDerivationPath = errors.New("derivation path not 5 elements")
	ErrElementOverflow           = errors.New("derivation path element > MaxUint32")
	ErrPubkeyMismatch            = errors.New("pubkey mismatch")
	ErrTooManyTweaks             = errors.New("both single and double tweak specified")
)
