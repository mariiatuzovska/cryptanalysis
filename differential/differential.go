package differential

import (
	"fmt"
	"log"
	"runtime"

	"github.com/mariiatuzovska/cryptanalysis/heys"
)

type (
	Differential struct {
		cipher *heys.Heys
		// encrypted *map[uint16]uint16
	}
	response struct {
		alpha  uint16
		branch Branch
	}
	Branch  map[uint16]float64
	DPTable map[uint16]Branch
)

var (
	limValues             = []float64{0.1, 0.0001, 0.0003, 0.00003, 0.00003}
	probabilityPerOneTime = float64(1) / float64(0x10000)
	alphas                = []uint16{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
		0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00,
		0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000}
)

func NewDifferential(h *heys.Heys) *Differential {
	// encrypted := make(map[uint16]uint16)
	// for i := 0; i < 0x10000; i++ {
	// 	block := heys.NewBlock(uint16(i))
	// 	for r := 0; r < 6; r++ {
	// 		h.RoundEncryptionBlock(block, r)
	// 	}
	// 	encrypted[uint16(i)] = block.Uint16()
	// }
	return &Differential{h} //, &encrypted}
}

func (dif *Differential) Search() *DPTable {

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	alphasChan, responseChan := make(chan uint16, 0x10000), make(chan response, 0x10000)
	result := make(DPTable)

	for i := 0; i < numCPU; i++ {
		go dif.ProbabilityDifference(alphasChan, responseChan) // numCPU separate goroutines
	}

	for _, alpha := range alphas {

		gamma, counter := make([]Branch, 6), 1
		gamma[0] = make(Branch)
		gamma[0][alpha] = 1 // starning gamma-list of diffenrences with Alpha and probability 1
		alphasChan <- alpha

		for round := 1; round < 6; round++ {
			i := 0
			gamma[round] = make(Branch)
			for {
				response := <-responseChan
				if aProbability, exist := gamma[round-1][response.alpha]; exist {
					for b, bProbability := range response.branch {
						if _, exist := gamma[round][b]; !exist {
							gamma[round][b] = bProbability * aProbability
						} else {
							gamma[round][b] = gamma[round][b] + (bProbability * aProbability)
						}
					}
				} else {
					log.Fatal("Unexpected alpha vzalas' neotkuda")
				}
				i++
				if i == counter {
					goto ResetCounter
				}
			}
		ResetCounter:
			counter = 0
			for a, aProbability := range gamma[round] {
				if aProbability < limValues[round-1] {
					delete(gamma[round], a)
				} else if round < 5 {
					alphasChan <- a
					counter++
				}
			}
			if len(gamma[round]) < 1 {
				fmt.Println(fmt.Sprintf("alpha 0x%x gone on round %d", alpha, round))
				goto Result
			}
		}
	Result:
		if len(gamma[5]) > 0 {
			result[alpha] = gamma[5]
		}
		fmt.Println(fmt.Sprintf("alpha 0x%x has %d betas", alpha, len(gamma[5])))
	}

	close(alphasChan)
	close(responseChan)

	return &result
}

func (dif *Differential) ProbabilityDifference(a chan uint16, resp chan response) { // sum_x [b = f(x ^ alpha) ^ f(x)]
	// encrypted := *dif.encrypted
	for {
		alpha, open := <-a
		if open && alpha != 0 {
			aTable := make(Branch)
			for x := 0; x < 0x10000; x++ {
				// b := encrypted[uint16(x)] ^ encrypted[uint16(x)^alpha] ^ 0xffff
				f, g := heys.NewBlock(uint16(x)), heys.NewBlock(uint16(x)^alpha)
				for r := 0; r < 6; r++ {
					dif.cipher.RoundEncryptionBlock(f, r)
					dif.cipher.RoundEncryptionBlock(g, r)
				}
				b := f.Uint16() ^ g.Uint16() ^ 0xffff
				if _, exist := aTable[b]; !exist {
					aTable[b] = 0
				}
				aTable[b] += probabilityPerOneTime
			}
			resp <- response{
				alpha:  alpha,
				branch: aTable,
			}
		} else {
			break
		}
	}
}
