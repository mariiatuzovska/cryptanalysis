package linear

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/mariiatuzovska/cryptanalysis/heys"
)

type (
	linearResponse struct {
		alpha       int
		probability map[int]float64
	}
)

var (
	limValues     = []float64{0.00015, 0.00015, 0.00015, 0.00015, 0.00012}
	limConcurency = 12000
	countOfText   = 8500
	alphas        = []int{
		0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
		0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070, 0x0080, 0x0090, 0x00a0, 0x00b0, 0x00c0, 0x00d0, 0x00e0, 0x00f0,
		0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700, 0x0800, 0x0900, 0x0a00, 0x0b00, 0x0c00, 0x0d00, 0x0e00, 0x0f00,
		0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000}
)

func Attack() *map[int]int {

	t1 := time.Now()

	texts, encryptedOneTime := make(map[int]bool), heys.EncryptAll()
	for i := 0; i < countOfText; i++ {
		x := rand.Int() & 0xffff
		if _, exist := texts[x]; !exist {
			texts[x] = true
			i++
		}
		i--
	}

	// encrypted := heys.EncryptAllWithKey()
	data, err := ioutil.ReadFile("community/encrypted.txt")
	if err != nil {
		log.Fatal(err)
	}
	encrypted := heys.ConvertDataToBlocks(data)

	approximations, scalars := make(map[int]map[int]float64), make([]int, 0x10000)
	file, err := ioutil.ReadFile("community/approximations.json")
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(file, &approximations)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 0x10000; i++ {
		с := 0
		for j := 0; j < 16; j++ {
			if (i>>j)&1 == 1 {
				с++
			}
		}
		scalars[i] = с & 1
	}

	sortedMap, probs := make(map[float64]map[int]int), make([]float64, 0)
	for alpha, aprox := range approximations {
		for beta, prob := range aprox {
			probs = append(probs, prob)
			sortedMap[prob] = map[int]int{alpha: beta}
		}
	}
	sort.Float64s(probs)
	if len(sortedMap) != len(probs) {
		log.Fatal("Sort failed")
	}

	fmt.Println(fmt.Sprintf("Starting to process %d aproximations", len(probs)))

	keyCandidate := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		keyCandidate[x] = 0
	}

	for j := len(probs) - 1; j > -1; j-- {
		aprox := sortedMap[probs[j]]
		for alpha, beta := range aprox {
			fmt.Println(fmt.Sprintf("Approximating 0x%04x -- 0x%04x with probability -- %f -- expected %d", alpha, beta, probs[j], j))
			res := make([]int, 0x10000)
			for key := 0; key < 0x10000; key++ {
				E := 0 // кол-во единиц
				for block := range texts {
					if (scalars[alpha&encryptedOneTime[block^key]] ^ scalars[beta&encrypted[block]]) == 1 {
						E++
					}
				}
				U := math.Abs(float64(countOfText - E - E))
				res[key] = int(U)
			}
			maxU := 0
			for key := 0; key < 0x10000; key++ {
				if res[key] > maxU {
					maxU = res[key]
				}
			}
			var limU float64 = 0.7 * float64(maxU)
			for key := 0; key < 0x10000; key++ {
				if res[key] > int(limU) {
					keyCandidate[key] += res[key]
				}
			}
		}
	}

	result := make(map[int]int)
	for x := 0; x < 0x10000; x++ {
		if keyCandidate[x] > limConcurency {
			result[x] = keyCandidate[x]
		}
	}

	t2 := time.Now().Sub(t1)
	fmt.Println("Runs", t2.Milliseconds(), "ms")

	return &result
}

func Search() *map[int]map[int]float64 {

	t1 := time.Now()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	responseChan := make(chan linearResponse, len(alphas))

	for _, alph := range alphas {

		go func(alpha int, resp chan linearResponse) {

			gamma, g := make([]float64, 0x10000), make([]float64, 0x10000)
			for x := 0; x < 0x10000; x++ {
				gamma[x] = -1.0
			}
			gamma[alpha] = 1.0
			for round := 1; round < 6; round++ {
				for x := 0; x < 0x10000; x++ {
					g[x] = -1.0
				}
				for i := 0; i < 0x10000; i++ {
					if gamma[i] < 0.0 {
						continue
					}
					approximations := approximate(i)
					for block, probNum := range approximations {
						p := g[block]
						if p < 0.0 {
							p = 0.0
						}
						corelation := float64(1.0) - float64(2)*(float64(probNum)/float64(0x10000))
						g[block] = p + (corelation * corelation * gamma[i])
					}
				}
				for x := 0; x < 0x10000; x++ {
					gamma[x] = -1.0
					if g[x] > limValues[round-1] {
						gamma[x] = g[x]
					}
				}
			}
			res := make(map[int]float64)
			for x := 0; x < 0x10000; x++ {
				if gamma[x] > 0.0 {
					res[x] = gamma[x]
				}
			}
			resp <- linearResponse{alpha, res}

		}(alph, responseChan)

	}

	result, mutex := make(map[int]map[int]float64), sync.Mutex{}
	for i := 0; i < len(alphas); i++ {
		response := <-responseChan
		mutex.Lock()
		result[response.alpha] = response.probability
		mutex.Unlock()
	}

	close(responseChan)

	t2 := time.Now().Sub(t1)
	fmt.Println("Runs", t2.Microseconds(), "ms")

	return &result
}

func approximate(alpha int) map[int]int {

	result, scalars := make(map[int]int), make([]int, 16)

	for i := 0; i < 16; i++ {
		с := 0
		for j := 0; j < 16; j++ {
			if ((i >> j) & 1) == 1 {
				с++
			}
		}
		scalars[i] = с & 1
	}

	linearApproximation := make([][]int, 16)
	for a := 0; a < 16; a++ {
		linearApproximation[a] = make([]int, 16)
		for b := 0; b < 16; b++ {
			linearApproximation[a][b] = 0
			for x := 0; x < 16; x++ {
				linearApproximation[a][b] += scalars[a&x] ^ scalars[b&heys.SBlocks[x]]
			}
		}
	}

	a0 := (alpha >> 0) & 0xf
	a1 := (alpha >> 4) & 0xf
	a2 := (alpha >> 8) & 0xf
	a3 := (alpha >> 12) & 0xf

	for beta := 0; beta < 0x10000; beta++ {

		b0 := (beta >> 0) & 0xf
		b1 := (beta >> 4) & 0xf
		b2 := (beta >> 8) & 0xf
		b3 := (beta >> 12) & 0xf

		e0 := linearApproximation[a0][b0]
		e1 := linearApproximation[a1][b1]
		e2 := linearApproximation[a2][b2]
		e3 := linearApproximation[a3][b3]

		z0 := 16 - e0
		z1 := 16 - e1
		z2 := 16 - e2
		z3 := 16 - e3

		num := 0

		num += e0 * z1 * z2 * z3
		num += z0 * e1 * z2 * z3
		num += z0 * z1 * e2 * z3
		num += z0 * z1 * z2 * e3

		num += z0 * e1 * e2 * e3
		num += e0 * z1 * e2 * e3
		num += e0 * e1 * z2 * e3
		num += e0 * e1 * e2 * z3

		if num != 0x10000/2 {
			result[heys.Permutation(beta)] = num
			// fmt.Println(fmt.Sprintf("0x%04x -- %d", b, probNum))
		}
	}

	return result
}
