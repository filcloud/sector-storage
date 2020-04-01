//+build cgo

package ffiwrapper

import (
	"context"
	"math"

	"golang.org/x/xerrors"

	"go.opencensus.io/trace"

	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/filecoin-ffi/generated"
	"github.com/filecoin-project/specs-actors/actors/abi"
	"github.com/filecoin-project/specs-storage/storage"

	"github.com/filecoin-project/sector-storage/stores"
)

type ReadCallback func(ctx context.Context, miner uint64, sectorID uint64, cacheID string, offset uint64, size uint64, buf []byte) uint64

type InternalReadCallback func(ctx context.Context, info ffi.PrivateSectorInfo, miner uint64, sectorID uint64, cacheID string, offset uint64, size uint64, buf []byte) uint64

var DefaultReadCallback InternalReadCallback

func (sb *Sealer) SetNetReadCallback(cb ReadCallback, tryLocal bool) {
	sb.readCallback = func(ctx context.Context, info ffi.PrivateSectorInfo, miner uint64, sectorID uint64, cacheID string, offset uint64, size uint64, buf []byte) uint64 {
		if tryLocal {
			n := DefaultReadCallback(ctx, info, miner, sectorID, cacheID, offset, size, buf)
			if n != math.MaxUint64 {
				return n
			}
		}
		return cb(ctx, miner, sectorID, cacheID, offset, size, buf)
	}
}

func (sb *Sealer) buildNetReadCallback(ctx context.Context, info ffi.SortedPrivateSectorInfo, miner uint64) ffi.NetReadCallback {
	sectors := make(map[uint64]ffi.PrivateSectorInfo)
	for _, f := range info.Values() {
		sectors[uint64(f.SectorNumber)] = f
	}

	// TODO: local cache according to same sectorID/cacheID/offset/size
	return func(sectorID uint64, cacheID string, offset uint64, size uint64, buf []byte) uint64 {
		f, ok := sectors[sectorID]
		if !ok {
			panic("sector not found") // should never go here
		}
		return sb.readCallback(ctx, f, miner, sectorID, cacheID, offset, size, buf)
	}
}

func (sb *Sealer) ComputeElectionPoSt(ctx context.Context, miner abi.ActorID, sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, winners []abi.PoStCandidate) ([]abi.PoStProof, error) {
	challengeSeed[31] = 0

	privsects, err := sb.pubSectorToPriv(ctx, miner, sectorInfo, nil) // TODO: faults
	if err != nil {
		return nil, err
	}

	generated.NetReadCallbackLocker.Lock()
	defer generated.NetReadCallbackLocker.Unlock()

	return ffi.GeneratePoSt(miner, privsects, challengeSeed, winners, sb.buildNetReadCallback(ctx, privsects, uint64(miner)))
}

func (sb *Sealer) GenerateFallbackPoSt(ctx context.Context, miner abi.ActorID, sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, faults []abi.SectorNumber) (storage.FallbackPostOut, error) {
	privsectors, err := sb.pubSectorToPriv(ctx, miner, sectorInfo, faults)
	if err != nil {
		return storage.FallbackPostOut{}, err
	}

	challengeCount := fallbackPostChallengeCount(uint64(len(sectorInfo)), uint64(len(faults)))
	challengeSeed[31] = 0

	generated.NetReadCallbackLocker.Lock()
	defer generated.NetReadCallbackLocker.Unlock()
	netReadCallback := sb.buildNetReadCallback(ctx, privsectors, uint64(miner))

	candidates, err := ffi.GenerateCandidates(miner, challengeSeed, challengeCount, privsectors, netReadCallback)
	if err != nil {
		return storage.FallbackPostOut{}, err
	}

	winners := make([]abi.PoStCandidate, len(candidates))
	for idx := range winners {
		winners[idx] = candidates[idx].Candidate
	}

	proof, err := ffi.GeneratePoSt(miner, privsectors, challengeSeed, winners, netReadCallback)
	return storage.FallbackPostOut{
		PoStInputs: ffiToStorageCandidates(candidates),
		Proof:      proof,
	}, err
}

func (sb *Sealer) GenerateEPostCandidates(ctx context.Context, miner abi.ActorID, sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, faults []abi.SectorNumber) ([]storage.PoStCandidateWithTicket, error) {
	privsectors, err := sb.pubSectorToPriv(ctx, miner, sectorInfo, faults)
	if err != nil {
		return nil, err
	}

	challengeSeed[31] = 0

	generated.NetReadCallbackLocker.Lock()
	defer generated.NetReadCallbackLocker.Unlock()

	challengeCount := ElectionPostChallengeCount(uint64(len(sectorInfo)), uint64(len(faults)))
	pc, err := ffi.GenerateCandidates(miner, challengeSeed, challengeCount, privsectors, sb.buildNetReadCallback(ctx, privsectors, uint64(miner)))
	if err != nil {
		return nil, err
	}

	return ffiToStorageCandidates(pc), nil
}

func ffiToStorageCandidates(pc []ffi.PoStCandidateWithTicket) []storage.PoStCandidateWithTicket {
	out := make([]storage.PoStCandidateWithTicket, len(pc))
	for i := range out {
		out[i] = storage.PoStCandidateWithTicket{
			Candidate: pc[i].Candidate,
			Ticket:    pc[i].Ticket,
		}
	}

	return out
}

func (sb *Sealer) pubSectorToPriv(ctx context.Context, mid abi.ActorID, sectorInfo []abi.SectorInfo, faults []abi.SectorNumber) (ffi.SortedPrivateSectorInfo, error) {
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

		postProofType, err := s.RegisteredProof.RegisteredPoStProof()
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

	return ffi.NewSortedPrivateSectorInfo(out...), nil
}

var _ Verifier = ProofVerifier

type proofVerifier struct{}

var ProofVerifier = proofVerifier{}

func (proofVerifier) VerifySeal(info abi.SealVerifyInfo) (bool, error) {
	return ffi.VerifySeal(info)
}

func (proofVerifier) VerifyElectionPost(ctx context.Context, info abi.PoStVerifyInfo) (bool, error) {
	return verifyPost(ctx, info)
}

func (proofVerifier) VerifyFallbackPost(ctx context.Context, info abi.PoStVerifyInfo) (bool, error) {
	return verifyPost(ctx, info)
}

func verifyPost(ctx context.Context, info abi.PoStVerifyInfo) (bool, error) {
	_, span := trace.StartSpan(ctx, "VerifyPoSt")
	defer span.End()

	info.Randomness[31] = 0

	return ffi.VerifyPoSt(info)
}
