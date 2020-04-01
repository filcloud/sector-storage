package ffiwrapper

import (
	"github.com/filecoin-project/specs-actors/actors/abi"
	logging "github.com/ipfs/go-log/v2"

	ffi "github.com/filecoin-project/filecoin-ffi"
)

var log = logging.Logger("ffiwrapper")

type Sealer struct {
	sealProofType abi.RegisteredSealProof
	ssize         abi.SectorSize // a function of sealProofType and postProofType

	sectors  SectorProvider
	stopping chan struct{}

	postCallback PoStCallback
	generatePoSt func (abi.ActorID, ffi.SortedPrivateSectorInfo, abi.PoStRandomness, string, bool) ([]abi.PoStProof, error)
}

func (sb *Sealer) Stop() {
	close(sb.stopping)
}

func (sb *Sealer) SectorSize() abi.SectorSize {
	return sb.ssize
}

func (sb *Sealer) SealProofType() abi.RegisteredSealProof {
	return sb.sealProofType
}
