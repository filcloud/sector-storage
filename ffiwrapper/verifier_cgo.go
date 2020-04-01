// +build cgo

package ffiwrapper

import (
	"context"

	"golang.org/x/xerrors"

	"go.opencensus.io/trace"

	"github.com/filecoin-project/specs-actors/actors/abi"

	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/filecoin-ffi/generated"

	"github.com/filecoin-project/sector-storage/stores"
)

func (sb *Sealer) TreeProve(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness, j, i []uint64, numSectorsPerChunk uint64, isWinningPoSt bool) (string, error) {
	if isWinningPoSt {
		privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWinningPoStProof, true) // TODO: FAULTS?
		if err != nil {
			return "", err
		}
		return ffi.TreeProve(privsectors, randomness, j, i, numSectorsPerChunk, isWinningPoSt)
	} else {
		privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWindowPoStProof, true) // TODO: FAULTS?
		if err != nil {
			return "", err
		}
		return ffi.TreeProve(privsectors, randomness, j, i, numSectorsPerChunk, isWinningPoSt)
	}
}

func (sb *Sealer) GenerateWinningPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, error) {
	randomness[31] = 0                                                                                                    // TODO: Not correct, fixme
	privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWinningPoStProof) // TODO: FAULTS?
	if err != nil {
		return nil, err
	}

	generated.GlobalWinningPoStCallbackLocker.Lock()
	defer generated.GlobalWinningPoStCallbackLocker.Unlock()

	merkleTreeProofCallback := sb.buildMerkleTreeProofCallback(ctx, uint64(minerID), privsectors, randomness, true)

	return ffi.GenerateWinningPoSt(minerID, privsectors, randomness, merkleTreeProofCallback)
}

func (sb *Sealer) GenerateWindowPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, error) {
	randomness[31] = 0                                                                                                   // TODO: Not correct, fixme
	privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWindowPoStProof) // TODO: FAULTS?
	if err != nil {
		return nil, err
	}

	generated.GlobalWindowPoStCallbackLocker.Lock()
	defer generated.GlobalWindowPoStCallbackLocker.Unlock()

	merkleTreeProofCallback := sb.buildMerkleTreeProofCallback(ctx, uint64(minerID), privsectors, randomness, false)

	return ffi.GenerateWindowPoSt(minerID, privsectors, randomness, merkleTreeProofCallback)
}

func (sb *Sealer) pubSectorToPriv(ctx context.Context, mid abi.ActorID, sectorInfo []abi.SectorInfo, faults []abi.SectorNumber, rpt func(abi.RegisteredProof) (abi.RegisteredProof, error), noSort ...bool) (ffi.SortedPrivateSectorInfo, error) {
	fmap := map[abi.SectorNumber]struct{}{}
	for _, fault := range faults {
		fmap[fault] = struct{}{}
	}

	var out []ffi.PrivateSectorInfo
	for _, s := range sectorInfo {
		if _, faulty := fmap[s.SectorNumber]; faulty {
			continue
		}

		paths, done, err := sb.sectors.AcquireSector(ctx, abi.SectorID{Miner: mid, Number: s.SectorNumber}, stores.FTCache|stores.FTSealed, 0, false)
		if err != nil {
			return ffi.SortedPrivateSectorInfo{}, xerrors.Errorf("acquire sector paths: %w", err)
		}
		done() // TODO: This is a tiny bit suboptimal

		postProofType, err := rpt(s.RegisteredProof)
		if err != nil {
			return ffi.SortedPrivateSectorInfo{}, xerrors.Errorf("acquiring registered PoSt proof from sector info %+v: %w", s, err)
		}

		out = append(out, ffi.PrivateSectorInfo{
			CacheDirPath:     paths.Cache,
			PoStProofType:    postProofType,
			SealedSectorPath: paths.Sealed,
			SectorInfo:       s,
		})
	}

	if len(noSort) > 0 && noSort[0] {
		return ffi.NewPrivateSectorInfo(out...), nil
	}
	return ffi.NewSortedPrivateSectorInfo(out...), nil
}

var _ Verifier = ProofVerifier

type proofVerifier struct{}

var ProofVerifier = proofVerifier{}

func (proofVerifier) VerifySeal(info abi.SealVerifyInfo) (bool, error) {
	return ffi.VerifySeal(info)
}

func (proofVerifier) VerifyWinningPoSt(ctx context.Context, info abi.WinningPoStVerifyInfo) (bool, error) {
	info.Randomness[31] = 0 // TODO: Not correct, fixme
	_, span := trace.StartSpan(ctx, "VerifyWinningPoSt")
	defer span.End()

	return ffi.VerifyWinningPoSt(info)
}

func (proofVerifier) VerifyWindowPoSt(ctx context.Context, info abi.WindowPoStVerifyInfo) (bool, error) {
	info.Randomness[31] = 0 // TODO: Not correct, fixme
	_, span := trace.StartSpan(ctx, "VerifyWindowPoSt")
	defer span.End()

	return ffi.VerifyWindowPoSt(info)
}

func (proofVerifier) GenerateWinningPoStSectorChallenge(ctx context.Context, proofType abi.RegisteredProof, minerID abi.ActorID, randomness abi.PoStRandomness, eligibleSectorCount uint64) ([]uint64, error) {
	randomness[31] = 0 // TODO: Not correct, fixme
	return ffi.GenerateWinningPoStSectorChallenge(proofType, minerID, randomness, eligibleSectorCount)
}
