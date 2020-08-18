// +build cgo

package ffiwrapper

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/filecoin-project/specs-actors/actors/abi"

	ffi "github.com/filecoin-project/filecoin-ffi"

	"github.com/filecoin-project/sector-storage/stores"

	"go.opencensus.io/trace"

	"github.com/filecoin-project/filecoin-ffi/generated"
)

func (sb *Sealer) TreeProve(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness, j, i []uint64, numSectorsPerChunk uint64, isWinningPoSt bool) (string, error) {
	if isWinningPoSt {
		privsectors, skipped, done, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredSealProof.RegisteredWinningPoStProof, true) // TODO: FAULTS?
		if err != nil {
			return "", err
		}
		defer done()
		if len(skipped) > 0 {
			return "", xerrors.Errorf("pubSectorToPriv skipped sectors: %+v", skipped)
		}
		return ffi.TreeProve(privsectors, randomness, j, i, numSectorsPerChunk, isWinningPoSt)
	} else {
		privsectors, skipped, done, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredSealProof.RegisteredWindowPoStProof, true) // TODO: FAULTS?
		if err != nil {
			return "", err
		}
		defer done()
		if len(skipped) > 0 {
			return "", xerrors.Errorf("pubSectorToPriv skipped sectors: %+v", skipped)
		}
		return ffi.TreeProve(privsectors, randomness, j, i, numSectorsPerChunk, isWinningPoSt)
	}
}

func (sb *Sealer) GenerateWinningPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, error) {
	randomness[31] &= 0x3f
	privsectors, skipped, done, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredSealProof.RegisteredWinningPoStProof) // TODO: FAULTS?
	if err != nil {
		return nil, err
	}
	defer done()
	if len(skipped) > 0 {
		return nil, xerrors.Errorf("pubSectorToPriv skipped sectors: %+v", skipped)
	}

	generated.GlobalWinningPoStCallbackLocker.Lock()
	defer generated.GlobalWinningPoStCallbackLocker.Unlock()

	if sb.postCallback == nil { // local
		return sb.generatePoSt(minerID, privsectors, randomness, "", true)
	}

	privsectors, proofsStr, err := sb.postCallback(ctx, privsectors, string(randomness), true)
	if err != nil {
		return nil, err
	}

	return sb.generatePoSt(minerID, privsectors, randomness, proofsStr, true)
}

func (sb *Sealer) GenerateWindowPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, []abi.SectorID, error) {
	randomness[31] &= 0x3f
	privsectors, skipped, done, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredSealProof.RegisteredWindowPoStProof)
	if err != nil {
		return nil, nil, xerrors.Errorf("gathering sector info: %w", err)
	}
	defer done()

	generated.GlobalWindowPoStCallbackLocker.Lock()
	defer generated.GlobalWindowPoStCallbackLocker.Unlock()

	if sb.postCallback == nil { // local
		proof, err := sb.generatePoSt(minerID, privsectors, randomness, "", false)
		return proof, skipped, err
	}

	remainingPrivsectors, proofsStr, err := sb.postCallback(ctx, privsectors, string(randomness), false)
	if err != nil {
		return nil, nil, err
	}

	rpm := make(map[abi.SectorNumber]struct{})
	for _, s := range remainingPrivsectors.Values() {
		rpm[s.SectorNumber] = struct{}{}
	}
	for _, s := range privsectors.Values() {
		if _, ok := rpm[s.SectorNumber]; !ok {
			skipped = append(skipped, abi.SectorID{Miner: minerID, Number: s.SectorNumber})
		}
	}

	proof, err := sb.generatePoSt(minerID, remainingPrivsectors, randomness, proofsStr, false)
	return proof, skipped, err
}

func (sb *Sealer) pubSectorToPriv(ctx context.Context, mid abi.ActorID, sectorInfo []abi.SectorInfo, faults []abi.SectorNumber, rpt func(abi.RegisteredSealProof) (abi.RegisteredPoStProof, error), noSort ...bool) (ffi.SortedPrivateSectorInfo, []abi.SectorID, func(), error) {
	fmap := map[abi.SectorNumber]struct{}{}
	for _, fault := range faults {
		fmap[fault] = struct{}{}
	}

	var doneFuncs []func()
	done := func() {
		for _, df := range doneFuncs {
			df()
		}
	}

	var skipped []abi.SectorID
	var out []ffi.PrivateSectorInfo
	for _, s := range sectorInfo {
		if _, faulty := fmap[s.SectorNumber]; faulty {
			continue
		}

		sid := abi.SectorID{Miner: mid, Number: s.SectorNumber}

		paths, d, err := sb.sectors.AcquireSector(ctx, sid, stores.FTCache|stores.FTSealed, 0, stores.PathStorage)
		if err != nil {
			log.Warnw("failed to acquire sector, skipping", "sector", sid, "error", err)
			skipped = append(skipped, sid)
			continue
		}
		doneFuncs = append(doneFuncs, d)

		postProofType, err := rpt(s.SealProof)
		if err != nil {
			done()
			return ffi.SortedPrivateSectorInfo{}, nil, nil, xerrors.Errorf("acquiring registered PoSt proof from sector info %+v: %w", s, err)
		}

		out = append(out, ffi.PrivateSectorInfo{
			CacheDirPath:     paths.Cache,
			PoStProofType:    postProofType,
			SealedSectorPath: paths.Sealed,
			SectorInfo:       s,
		})
	}

	if len(noSort) > 0 && noSort[0] {
		return ffi.NewPrivateSectorInfo(out...), skipped, done, nil
	}
	return ffi.NewSortedPrivateSectorInfo(out...), skipped, done, nil
}

var _ Verifier = ProofVerifier

type proofVerifier struct{}

var ProofVerifier = proofVerifier{}

func (proofVerifier) VerifySeal(info abi.SealVerifyInfo) (bool, error) {
	return ffi.VerifySeal(info)
}

func (proofVerifier) VerifyWinningPoSt(ctx context.Context, info abi.WinningPoStVerifyInfo) (bool, error) {
	info.Randomness[31] &= 0x3f
	_, span := trace.StartSpan(ctx, "VerifyWinningPoSt")
	defer span.End()

	return ffi.VerifyWinningPoSt(info)
}

func (proofVerifier) VerifyWindowPoSt(ctx context.Context, info abi.WindowPoStVerifyInfo) (bool, error) {
	info.Randomness[31] &= 0x3f
	_, span := trace.StartSpan(ctx, "VerifyWindowPoSt")
	defer span.End()

	return ffi.VerifyWindowPoSt(info)
}

func (proofVerifier) GenerateWinningPoStSectorChallenge(ctx context.Context, proofType abi.RegisteredPoStProof, minerID abi.ActorID, randomness abi.PoStRandomness, eligibleSectorCount uint64) ([]uint64, error) {
	randomness[31] &= 0x3f
	return ffi.GenerateWinningPoStSectorChallenge(proofType, minerID, randomness, eligibleSectorCount)
}
