package ffiwrapper

import (
	"github.com/filecoin-project/specs-actors/actors/abi"
	logging "github.com/ipfs/go-log/v2"
)

var log = logging.Logger("ffiwrapper")

type Sealer struct {
	sealProofType abi.RegisteredProof
	postProofType abi.RegisteredProof
	ssize         abi.SectorSize // a function of sealProofType and postProofType

	sectors  SectorProvider
	stopping chan struct{}

	readCallback InternalReadCallback
}

func fallbackPostChallengeCount(sectors uint64, faults uint64) uint64 {
	challengeCount := ElectionPostChallengeCount(sectors, faults)
	if challengeCount > MaxFallbackPostChallengeCount {
		return MaxFallbackPostChallengeCount
	}
	return challengeCount
}

func (sb *Sealer) Stop() {
	close(sb.stopping)
}

func (sb *Sealer) SectorSize() abi.SectorSize {
	return sb.ssize
}

func (sb *Sealer) SealProofType() abi.RegisteredProof {
	return sb.sealProofType
}

func (sb *Sealer) PoStProofType() abi.RegisteredProof {
	return sb.postProofType
}
