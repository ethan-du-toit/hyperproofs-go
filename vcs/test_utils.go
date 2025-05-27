package vcs

/*
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4
#cgo CFLAGS: -DMCLBN_FP_UNIT_SIZE=4
#cgo LDFLAGS: -lmcl
#include <mcl/bn.h>
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	//"testing"
	//"strconv"
	"github.com/alinush/go-mcl"
	//"github.com/herumi/mcl/ffi/go/mcl"
)

// export CGO_CFLAGS="-DMCLBN_FP_UNIT_SIZE=4"

type Node struct {
	addr int64
	nonce int64
	val int64
}

const addrOffset int = 43
const nonceOffset int = 22
const valOffset int = 1
const padding int = 0x0

func getKeyValuesFr(db map[uint64]mcl.Fr) ([]uint64, []mcl.Fr) {

	keys := make([]uint64, 0, len(db))
	values := make([]mcl.Fr, 0, len(db))
	for k, v := range db {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}

func getKeyValuesG1(db map[uint64]mcl.G1) ([]uint64, []mcl.G1) {

	keys := make([]uint64, 0, len(db))
	values := make([]mcl.G1, 0, len(db))
	for k, v := range db {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}

func fillRange(aFr *[]mcl.Fr, start uint64, stop uint64, wg *sync.WaitGroup) {
	for i := start; i < stop; i++ {
		(*aFr)[i].Random()
	}
	wg.Done()
}

func GenerateVector(N uint64) []mcl.Fr {
	aFr := make([]mcl.Fr, N)

	// Initialize all accounts with default values
	for i := uint64(0); i < N; i++ {
		var node Node
		node.addr = 0
		node.nonce = 0
		node.val = 1
		
		var nodeElement int64 = node.val << valOffset
		aFr[i].SetInt64(nodeElement)
	}

	return aFr
}

func SaveVector(N uint64, aFr []mcl.Fr) {
	folderPath := "pkvk/"
	os.MkdirAll(folderPath, os.ModePerm)
	fileName := folderPath + "/Vec.data"

	f, err := os.Create(fileName)
	check(err)
	fmt.Println(fileName)

	intBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(intBytes, N)
	_, err = f.Write(intBytes)
	check(err)

	for i := uint64(0); i < N; i++ {
		_, err = f.Write(aFr[i].Serialize())
		check(err)
	}
	fmt.Println("Dumped ", fileName)
	defer f.Close()
}

func LoadVector(N uint64, folderPath string) []mcl.Fr {

	fileName := folderPath + "/Vec.data"

	f, err := os.Open(fileName)
	check(err)

	var n uint64
	data := make([]byte, 8)

	_, err = f.Read(data)

	n = binary.LittleEndian.Uint64(data)

	if N > n {
		panic("Vec Load Error: There is not enough to read")
	}

	dataFr := make([]byte, GetFrByteSize())
	aFr := make([]mcl.Fr, N)

	for i := uint64(0); i < N; i++ {
		_, err = f.Read(dataFr)
		check(err)
		aFr[i].Deserialize(dataFr)
	}

	defer f.Close()
	return aFr
}

// Export the proofs in the 2D format for the VCS API
func GetProofVecFromDb(proofs_db map[uint64][]mcl.G1, indexVec []uint64) [][]mcl.G1 {
	proofVec := make([][]mcl.G1, len(indexVec))

	for i := range indexVec {
		proofVec[i] = make([]mcl.G1, len(proofs_db[indexVec[i]]))
		copy(proofVec[i], proofs_db[indexVec[i]])
	}
	return proofVec
}