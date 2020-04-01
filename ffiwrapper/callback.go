package ffiwrapper

import (
	"context"

	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/specs-actors/actors/abi"
)

type MerkleTreeProofCallback func(ctx context.Context, miner uint64, info ffi.SortedPrivateSectorInfo, numSectorsPerChunk uint64, randomness string, isWinningPoSt bool) string

func (sb *Sealer) SetMerkleTreeProofCallback(cb MerkleTreeProofCallback) {
	sb.merkleTreeProofCallback = cb
}

func (sb *Sealer) buildMerkleTreeProofCallback(ctx context.Context, miner uint64, info ffi.SortedPrivateSectorInfo, randomness abi.PoStRandomness, isWinningPoSt bool) ffi.MerkleTreeProofCallback {
	return func(numSectorsPerChunk uint64, proofs []byte, proofsLen uint64) uint64 {
		var result []byte

		if sb.merkleTreeProofCallback == nil { // local
			loopNum := int(numSectorsPerChunk)
			if !isWinningPoSt {
				loopNum = 1
			}
			var sectors []ffi.PrivateSectorInfo
			var jj, ii []uint64
			ss := info.Values()
			for p := 0; p < loopNum; p++ {
				for q := 0; q < len(ss); q++ {
					k := uint64(p*len(ss) + q)
					j := k / numSectorsPerChunk
					i := k % numSectorsPerChunk
					sectors = append(sectors, ss[q])
					jj = append(jj, j)
					ii = append(ii, i)
				}
			}
			resultStr, err := ffi.TreeProve(ffi.NewPrivateSectorInfo(sectors...), randomness, jj, ii, numSectorsPerChunk, isWinningPoSt)
			if err != nil {
				log.Errorf("Build merkle tree proof: %s", err)
				return 0 // indicate error
			}
			result = []byte(resultStr)
		} else {
			result = []byte(sb.merkleTreeProofCallback(ctx, miner, info, numSectorsPerChunk, string(randomness), isWinningPoSt))
		}

		resultLen := uint64(len(result))
		if resultLen > proofsLen {
			log.Errorf("Build merkle tree proof: buffer is too small, needs length %d", resultLen)
			return 0 // indicate error
		}
		copy(proofs[:resultLen], result)
		return resultLen
	}
}
