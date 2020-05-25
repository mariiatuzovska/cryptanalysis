package differential

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/mariiatuzovska/cryptanalysis/heys"
)

type (
	differenceResponse struct {
		alpha       int
		probability map[int]float64
	}
	keyResponse struct {
		key         int
		concurrency int
	}
)

var (
	limValues     = []float64{0.1, 0.0001, 0.0001, 0.00005, 0.001}
	limConcurency = 10
	countOfText   = 16000
	alphas        = []int{
		0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
		0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070, 0x0080, 0x0090, 0x00a0, 0x00b0, 0x00c0, 0x00d0, 0x00e0, 0x00f0,
		0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700, 0x0800, 0x0900, 0x0a00, 0x0b00, 0x0c00, 0x0d00, 0x0e00, 0x0f00,
		0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000}
)

func Attack(alpha int, beta int) map[int]int {

	t1 := time.Now()

	texts, decrypted := make(map[int]bool), heys.DecryptAll()
	if countOfText > 0xf000 {
		for i := 0; i < countOfText; i++ {
			texts[i] = true
		}
	} else {
		for i := 0; i < countOfText; i++ {
			x := rand.Int() & 0xffff
			if _, exist := texts[x]; !exist {
				// if 0x000f&x != 0 && 0x00f0&x != 0 && 0x0f00&x != 0 && 0xf000&x != 0 {
				texts[x] = true
				i++
				// }
			}
			i--
		}
	}

	// encrypted := heys.EncryptAllWithKey()
	data, err := ioutil.ReadFile("community/encrypted.txt")
	if err != nil {
		log.Fatal(err)
	}
	encrypted := heys.ConvertDataToBlocks(data)

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	responseChan := make(chan keyResponse, 0x10000)

	result := make(map[int]int)

	fmt.Println(fmt.Sprintf("Attack for input differences 0x%04x : 0x%04x", alpha, beta))

	for key := 0; key < 0x10000; key++ {
		go func(resp chan keyResponse, txts map[int]bool, enc, dec []int, probablyKey, a, b int) {
			concurrency := 0
			for block := range txts {
				c1, c2 := enc[block], enc[block^a]
				if dec[c1^probablyKey]^dec[c2^probablyKey] == b {
					concurrency++
				}
			}
			resp <- keyResponse{
				key:         probablyKey,
				concurrency: concurrency,
			}
		}(responseChan, texts, encrypted, decrypted, key, alpha, beta)
	}

	mutex := sync.Mutex{}
	for x := 0; x < 0x10000; x++ {
		response := <-responseChan
		mutex.Lock()
		if response.concurrency > limConcurency {
			result[response.key] = response.concurrency
			// fmt.Println(fmt.Sprintf("key 0x%04x concurency %d", key, maxConcurency))
		}
		mutex.Unlock()
	}

	t2 := time.Now().Sub(t1)
	fmt.Println("Runs", t2.Milliseconds(), "ms")

	return result
}

func Search() *map[int]map[int]float64 {

	t1 := time.Now()

	result := make(map[int]map[int]float64)
	encrypted := heys.EncryptAll()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	responseChan := make(chan differenceResponse, len(alphas))

	for _, alpha := range alphas {

		go func(a int, resp chan differenceResponse, enc []int) {

			gamma := make([]float64, 0x10000)
			for x := 0; x < 0x10000; x++ {
				gamma[x] = -1.0
			}
			gamma[a] = 1.0
			for round := 1; round < 6; round++ {
				g := make([]float64, 0x10000)
				for x := 0; x < 0x10000; x++ {
					g[x] = -1.0
				}
				for diff := 0; diff < 0x10000; diff++ {
					dProb := gamma[diff]
					if dProb < 0.0 {
						continue
					}
					probs := differentialPropability(diff, enc)
					for x := 0; x < 0x10000; x++ {
						if probs[x] > -1.0 {
							currentProb := g[x]
							if currentProb < 0.0 {
								currentProb = 0.0
							}
							g[x] = currentProb + (probs[x] * dProb)
						}
					}
				}
				for x := 0; x < 0x10000; x++ {
					if g[x] < limValues[round-1] {
						g[x] = -1.0
					}
				}
				for x := 0; x < 0x10000; x++ {
					gamma[x] = g[x]
				}
			}

			res := make(map[int]float64)
			for x := 0; x < 0x10000; x++ {
				if gamma[x] > -1.0 {
					res[x] = gamma[x]
				}
			}

			resp <- differenceResponse{
				alpha:       a,
				probability: res,
			}

			fmt.Println(fmt.Sprintf("alpha 0x%04x has %d betas", a, len(res)))

		}(alpha, responseChan, encrypted)

	}

	mutex := sync.Mutex{}
	for i := 0; i < len(alphas); i++ {
		response := <-responseChan
		mutex.Lock()
		result[response.alpha] = response.probability
		mutex.Unlock()
	}

	close(responseChan)

	t2 := time.Now().Sub(t1)
	fmt.Println("Runs", t2.Milliseconds(), "ms")

	return &result
}

func differentialPropability(alpha int, encrypted []int) []float64 {
	frequence := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		frequence[x] = 0
	}
	for x := 0; x < 0x10000; x++ {
		frequence[encrypted[x]^encrypted[x^alpha]]++
	}
	probability := make([]float64, 0x10000)
	for x := 0; x < 0x10000; x++ {
		probability[x] = -1.0
		if frequence[x] != 0 {
			probability[x] = (float64(frequence[x]) / float64(0x10000))
		}
	}
	return probability
}
