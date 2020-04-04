package differential

import (
	"fmt"
	"log"
	"runtime"

	"github.com/mariiatuzovska/cryptanalysis/heys"
)

type (
	Differential struct {
		heys *heys.Heys
	}
	differenceResponse struct {
		alpha  uint16
		branch Branch
	}
	keyResponse struct {
		key   uint16
		count int
	}
	Branch  map[uint16]float64
	DPTable map[uint16]Branch
)

var (
	limValues             = []float64{0.124, 0.0003, 0.000085, 0.000035, 0.0000075}
	probabilityPerOneTime = float64(1) / float64(0x10000)
	countOfTexts          = 30000
	limKeyFrequency       = 50
	alphas                = []uint16{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
		0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00,
		0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000}
)

func NewDifferential(h *heys.Heys) *Differential {
	return &Differential{h}
}

func (dif *Differential) Attack(alpha, beta uint16) *map[uint16]int {

	textPair, decrypted := make(map[uint16]uint16), make(map[uint16]uint16)
	for x := uint32(0x1); x < 0x10000; x++ {
		block1 := heys.NewBlock(uint16(x))
		for r := 1; r < 7; r++ {
			dif.heys.RoundDecryptionBlock(block1, r)
		}
		decrypted[uint16(x)] = block1.Uint16()
		block2 := heys.NewBlock(block1.Uint16() ^ alpha)
		for r := 0; r < 6; r++ {
			dif.heys.RoundEncryptionBlock(block2, r)
		}
		decrypted[block2.Uint16()] = block1.Uint16() ^ alpha
		if 0x000f&x != 0 && 0x00f0&x != 0 && 0x0f00&x != 0 && 0xf000&x != 0 {
			block := heys.NewBlock(uint16(x))
			dif.heys.EncryptBlock(block)
			textPair[uint16(x)] = block.Uint16()
		}
	}

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	keyChan, responseChan, quite := make(chan uint16, 0x10000), make(chan keyResponse, 0x10000), make(chan bool, 0x10000)
	result := make(map[uint16]int)

	fmt.Println(fmt.Sprintf("Attack for input differences 0x%x : 0x%x", alpha, beta))

	for i := 0; i < numCPU; i++ {

		go func(k chan uint16, resp chan keyResponse, txtPair, dec *map[uint16]uint16, b uint16) {
			textPair, decrypted := *txtPair, *dec
			for {
				key, open := <-k
				if open && key != 0 {
					i, c := 0, 0
					for c1, c2 := range textPair {
						realDiff := decrypted[c1^uint16(key)] ^ decrypted[c2^uint16(key)]
						if realDiff == b {
							// 	fmt.Println(fmt.Sprintf("0x%x : 0x%x -- 0x%x : 0x%x  -- 0x%x : 0x%x -- difference %x",
							// 		c1, c2, c1^uint16(key), c2^uint16(key), decrypted[c1^uint16(key)], decrypted[c2^uint16(key)], realDiff))
							c++
						}
						i++
						if i == countOfTexts {
							goto Push
						}
					}
				Push:
					resp <- keyResponse{
						key:   key,
						count: c,
					}
				} else {
					break
				}
			}
		}(keyChan, responseChan, &textPair, &decrypted, beta)
	}

	for k := uint32(1); k < 0x10000; k++ {
		keyChan <- uint16(k)
	}

	counter := 0
	for {

		select {

		case response := <-responseChan:
			counter++
			quite <- false
			if response.count > limKeyFrequency {
				result[response.key] = response.count
			}
			if counter == 0xffff {
				quite <- true
			}

		case end := <-quite:
			if end {
				close(keyChan)
				close(responseChan)
				return &result
			}

		}
	}

}

func (dif *Differential) Search() *DPTable {

	encrypted := make(map[uint16]uint16)
	for i := 0; i < 0x10000; i++ {
		block := heys.NewBlock(uint16(i))
		dif.heys.EncryptBlock(block)
		encrypted[uint16(i)] = block.Uint16()
	}

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	alphasChan, responseChan := make(chan uint16, 0x10000), make(chan differenceResponse, 0x10000)
	result := make(DPTable)

	for i := 0; i < numCPU; i++ {
		go func(a chan uint16, response chan differenceResponse, enc map[uint16]uint16) { // sum_x [b = f(x ^ alpha) ^ f(x)]s
			for {
				alpha, open := <-a
				if open && alpha != 0 {
					aTable := make(Branch)
					for x := 0; x < 0x10000; x++ {
						b := enc[uint16(x)] ^ enc[uint16(x)^alpha] ^ 0xffff
						if _, exist := aTable[b]; !exist {
							aTable[b] = 0
						}
						aTable[b] += probabilityPerOneTime
					}
					response <- differenceResponse{
						alpha:  alpha,
						branch: aTable,
					}
				} else {
					break
				}
			}
		}(alphasChan, responseChan, encrypted)
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
				if aProbability < limValues[round-1] || a == 0 {
					delete(gamma[round], a)
					fmt.Println(fmt.Sprintf("alpha 0x%x beta 0x%x %f", alpha, a, aProbability))
				} else if round < 5 {
					alphasChan <- a
					counter++
				}
			}
			if len(gamma[round]) < 1 {
				fmt.Println(fmt.Sprintf("alpha 0x%x has gone on %d round", alpha, round))
				goto Result
			}
		}

	Result:
		if len(gamma[5]) > 0 {
			result[alpha] = gamma[5]
			fmt.Println(fmt.Sprintf("alpha 0x%x has %d betas", alpha, len(gamma[5])))
		}
	}

	close(alphasChan)
	close(responseChan)

	return &result
}
