package ffiwrapper

import (
	"context"

	"github.com/filecoin-project/specs-actors/actors/abi"

	ffi "github.com/filecoin-project/filecoin-ffi"
)

type PoStCallback func(ctx context.Context, info ffi.SortedPrivateSectorInfo, randomness string, isWinningPoSt bool) (ffi.SortedPrivateSectorInfo, string, error)

func (sb *Sealer) SetPoStCallback(cb PoStCallback) {
	sb.postCallback = cb
}

func (sb *Sealer) SetGeneratePoStCallback(cb func(abi.ActorID, ffi.SortedPrivateSectorInfo, abi.PoStRandomness, string, bool) ([]abi.PoStProof, error)) {
	sb.generatePoSt = cb
}
