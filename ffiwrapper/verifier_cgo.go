//+build cgo

package ffiwrapper

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	"go.opencensus.io/trace"

	"github.com/filecoin-project/specs-actors/actors/abi"

	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/filecoin-ffi/generated"

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

type NetReadStat struct {
	Name               string
	Times              uint64
	OffsetKinds        uint64
	Bytes              uint64
}

type NetReadStatAndCache struct {
	NetReadStat
	cacheByOffsetKinds map[string][]byte
	sync.Mutex
}

type NetReadStatAndCaches map[string]*NetReadStatAndCache

func (s NetReadStatAndCaches) String() string {
	sb := strings.Builder{}
	for _, v := range s {
		sb.WriteString(fmt.Sprintf(" %+v", v.NetReadStat))
	}
	return sb.String()
}

func ifStats() bool {
	s := strings.ToLower(os.Getenv("LOTUS_NET_READ_STATS"))
	return s == "true" || s == "1"
}

func (sb *Sealer) buildNetReadCallback(ctx context.Context, info ffi.SortedPrivateSectorInfo, miner uint64) (ffi.NetReadCallback, NetReadStatAndCaches) {
	sectors := make(map[uint64]ffi.PrivateSectorInfo)
	for _, f := range info.Values() {
		sectors[uint64(f.SectorNumber)] = f
	}

	var m sync.Mutex
	cache := make(map[string]*NetReadStatAndCache)

	return func(sectorID uint64, cacheID string, offset uint64, size uint64, buf []byte) (n uint64) {
		m.Lock()

		f, ok := sectors[sectorID]
		if !ok {
			panic("sector not found") // should never go here
		}

		k := fmt.Sprintf("%d-%s", sectorID, cacheID)
		s, ok := cache[k]
		if !ok {
			s = &NetReadStatAndCache{
				NetReadStat: NetReadStat{
					Name: k,
				},
				cacheByOffsetKinds: make(map[string][]byte),
			}
			cache[k] = s
		}
		s.Times++

		m.Unlock()

		s.Lock()
		kk := fmt.Sprintf("%d-%d", offset, size)
		b, ok := s.cacheByOffsetKinds[kk]
		s.Unlock()

		if !ok { // read and cache it
			n = sb.readCallback(ctx, f, miner, sectorID, cacheID, offset, size, buf)
			if n != math.MaxUint64 {
				b = make([]byte, n)
				copy(b, buf[:n])

				s.Lock()
				s.cacheByOffsetKinds[kk] = b
				s.OffsetKinds = uint64(len(s.cacheByOffsetKinds))
				s.Unlock()
			}
		} else { // cache exists
			n = uint64(len(b))
			copy(buf[:n], b)
		}

		s.Lock()
		s.Bytes += n
		s.Unlock()

		return n
	}, cache
}

func (sb *Sealer) GenerateWinningPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, error) {
	randomness[31] = 0                                                                                                    // TODO: Not correct, fixme
	privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWinningPoStProof) // TODO: FAULTS?
	if err != nil {
		return nil, err
	}

	generated.NetReadCallbackLocker.Lock()
	defer generated.NetReadCallbackLocker.Unlock()

	cb, cache := sb.buildNetReadCallback(ctx, privsectors, uint64(minerID))
	defer func() {
		if ifStats() {
			log.Infof("GenerateWinningPoSt read stats: %s", NetReadStatAndCaches(cache).String())
		}
	}()

	return ffi.GenerateWinningPoSt(minerID, privsectors, randomness, cb)
}

func (sb *Sealer) GenerateWindowPoSt(ctx context.Context, minerID abi.ActorID, sectorInfo []abi.SectorInfo, randomness abi.PoStRandomness) ([]abi.PoStProof, error) {
	randomness[31] = 0                                                                                                   // TODO: Not correct, fixme
	privsectors, err := sb.pubSectorToPriv(ctx, minerID, sectorInfo, nil, abi.RegisteredProof.RegisteredWindowPoStProof) // TODO: FAULTS?
	if err != nil {
		return nil, err
	}

	generated.NetReadCallbackLocker.Lock()
	defer generated.NetReadCallbackLocker.Unlock()

	cb, cache := sb.buildNetReadCallback(ctx, privsectors, uint64(minerID))
	defer func() {
		if ifStats() {
			log.Infof("GenerateWindowPoSt read stats: %s", NetReadStatAndCaches(cache).String())
		}
	}()

	return ffi.GenerateWindowPoSt(minerID, privsectors, randomness, cb)
}

func (sb *Sealer) pubSectorToPriv(ctx context.Context, mid abi.ActorID, sectorInfo []abi.SectorInfo, faults []abi.SectorNumber, rpt func(abi.RegisteredProof) (abi.RegisteredProof, error)) (ffi.SortedPrivateSectorInfo, error) {
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
