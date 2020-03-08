package differential

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/mariiatuzovska/cryptanalysis/heys"
)

type (
	Input struct {
		Heys *heys.Heys // black box of heys encryption
	}
	Response struct {
		a      uint16
		aTable Branch
	}
	Branch  map[uint16]float64
	DPTable map[uint16]Branch
)

var (
	dName                 = "Differential"
	dPName                = "Differential Probability"
	dPSName               = "Differential Probability Search"
	TotalRounds           = 6
	probabilityPerOneTime = float64(1) / float64(0x10000)
	basicQuantile         = []float64{0.125, 0.000195, 0.00004, 0.0000005, 0.00000002}

	dpTable chan DPTable
	mux     sync.Mutex

	numCPU = 8

	Alphas = []uint16{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
		0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00,
		0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000}

	nullTetrade = []uint16{0x000f, 0x00f0, 0x0f00, 0xf000}
)

func New(h *heys.Heys) *Input {

	if h == nil {
		log.Fatal("Fatal | Heys black box is null")
	}
	log.Print(fmt.Sprintf("%T | %s | NEW | quantile: %F \n", time.Now(), dName, basicQuantile))

	return &Input{
		Heys: h,
	}
}

func (in *Input) DifferentialSearch() DPTable {

	numCPU = runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	alphasChan, responseChan := make(chan uint16, 0x10000), make(chan Response, 0x10000)
	result := make(DPTable)

	for i := 0; i < numCPU; i++ {
		go in.DifferentialProbability(alphasChan, responseChan) // numCPU separate goroutines
	}

	for _, alpha := range Alphas {

		gamma, counter := make([]Branch, TotalRounds), 1
		gamma[0] = make(Branch)
		gamma[0][alpha] = 1 // starning gamma-list of diffenrences with Alpha and probability 1
		alphasChan <- alpha

		for round := 1; round < TotalRounds; round++ { // starting counter
			i := 0
			log.Print(fmt.Sprintf("%T | %s | STARTED | round %d for input alpha 0x%x\n", time.Now(), dPSName, round, alpha))
			gamma[round] = make(Branch)
			for {
				response := <-responseChan
				aProbability, exist := gamma[round-1][response.a]
				if exist {
					for b, bProbability := range response.aTable {
						if _, exist := gamma[round][b]; exist {
							gamma[round][b] = bProbability * aProbability
						} else {
							gamma[round][b] = gamma[round][b] + (bProbability * aProbability)
						}
					}
				}
				i++
				if i == counter {
					break
				}
			}
			counter = 0
			for a, aProbability := range gamma[round] {
				if aProbability < basicQuantile[round-1] || a == 0 {
					delete(gamma[round], a)
				} else if round < TotalRounds-1 {
					alphasChan <- a
					counter++
				}
			}
			if len(gamma[round]) < 1 {
				log.Print(fmt.Sprintf("%T | %s | STOP | too big quantile %F in round %d for input alpha 0x%x\n", time.Now(), dPSName, basicQuantile[round-1], round, alpha))
				break
			}
			log.Print(fmt.Sprintf("%T | %s | FINISH | round %d for input atpha 0x%x\n", time.Now(), dPSName, round, alpha))
		}
		result[alpha] = gamma[TotalRounds-1]
	}

	close(alphasChan)
	close(responseChan)

	return result
}

// DifferentialProbability precomputations for some aplpha
func (in *Input) DifferentialProbability(a chan uint16, response chan Response) { // sum_x [b = f(x ^ alpha) ^ f(x)]

	log.Print(fmt.Sprintf("%T | %s | OPENED | \n", time.Now(), dPName))
	for {
		alpha, open := <-a
		if open && alpha != 0 {
			// log.Print(fmt.Sprintf("%T | %s | STARTED | 0x%x\n", time.Now(), dPName, alpha))
			aTable := make(Branch)
			for x := uint32(0); x <= 0xffff; x++ {
				beta := in.Difference(uint16(x), alpha)
				if _, exist := aTable[beta]; !exist {
					aTable[beta] = probabilityPerOneTime
				} else {
					aTable[beta] += probabilityPerOneTime
				}
			}
			// log.Print(fmt.Sprintf("%T | %s | FINISHED | 0x%x\n", time.Now(), dPName, alpha))
			response <- Response{
				a:      alpha,
				aTable: aTable,
			}
		} else {
			log.Print(fmt.Sprintf("%T | %s | CLOSED | \n", time.Now(), dPName))
			break
		}
	}
}

// Difference b = f(x ^ alpha) ^ (f(x)^(-1))
func (in *Input) Difference(x, alpha uint16) uint16 {

	f, g := x, (x ^ alpha)
	for r := 0; r < TotalRounds; r++ {
		f, _ = in.Heys.RoundEncryptionBlock(f, r)
		g, _ = in.Heys.RoundEncryptionBlock(g, r)
	}
	return f ^ g ^ 0xffff
}

// DifferentialProbabilityRoutine for creating full table
// ~ 5 min
func (in *Input) DifferentialProbabilityRoutine() *DPTable {

	numCPU = runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	dPTable := make(DPTable)
	a, response, quite := make(chan uint16, 0x10000), make(chan Response, numCPU*3), make(chan bool, 10)

	for i := 0; i < numCPU; i++ {
		go in.DifferentialProbability(a, response)
	}
	for x := uint32(0); x < 0x10000; x++ {
		a <- uint16(x)
	}
	for { // main routine waits for all
		select {
		case resp := <-response:
			dPTable[resp.a] = resp.aTable // has been processed
			quite <- false
			if len(dPTable) > 0xfffe {
				quite <- true
			}
		case end := <-quite:
			if end {
				close(a)
				close(response)
				// close(quite)
				log.Print(fmt.Sprintf("%T | %s | (@_@) | ALL PROCESS HAS BEEN FINISHED\n", time.Now(), dPName))
				return &dPTable
			}
		}
	}
}

func (table *DPTable) SaveTable(path string) error {

	a, err := json.MarshalIndent(table, "", "	")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, a, os.ModePerm)
}

func NewTable(path string) (*DPTable, error) {

	var file []byte
	table := new(DPTable)
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(file, table)
	if err != nil {
		return nil, err
	}

	return table, nil
}
