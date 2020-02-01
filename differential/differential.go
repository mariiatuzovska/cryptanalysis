package differential

import (
	"github.com/mariiatuzovska/ciphers/heys"
	"log"
)

type (
	Input struct {
		Heys        *heys.Heys // black box
		Alpha       uint16     // difference
		Quantile    []float32  // multiple of lim values
		Round       int        // counter
		TotalRounds int
	}
	Branch map[uint16]float32
)

func New(h *heys.Heys, alpha uint16, quantile []float32, rounds int) *Input {
	return &Input{
		Heys:        h,
		Alpha:       alpha,
		Quantile:    quantile,
		TotalRounds: rounds,
	}
}

func (in *Input) DifferentialSearch() *[]Branch {

	gamma := make([]Branch, in.TotalRounds)
	gamma[0] = make(Branch)
	gamma[0][in.Alpha] = 1 // starning gamma-list of diffenrences with Alpha and probability 1

	for in.Round = 1; in.Round < in.TotalRounds; in.Round++ { // starting counter
		gamma[in.Round] = make(Branch)
		sBox, err := in.DifferentialProbabilitySBox()
		if err != nil {
			log.Fatal(err)
		}
		for a, aProbability := range gamma[in.Round-1] {
			for b, bProbability := range sBox[a] {
				_, exist := gamma[in.Round][uint16(b)]
				if exist == false {
					gamma[in.Round][uint16(b)] = aProbability * (float32(bProbability) / 16)
				} else {
					gamma[in.Round][uint16(b)] = aProbability*(float32(bProbability)/16) + gamma[in.Round][uint16(b)]
				}
			}
			for b, bProbability := range gamma[in.Round] {
				if bProbability <= in.Quantile[in.Round-1] {
					delete(gamma[in.Round], b)
				}
			}
		}
	}

	return &gamma
}

func (in *Input) DifferentialProbabilitySBox() (dP [16][16]uint16, err error) {

	for x := 0; x < 16; x++ {
		for a := 0; a < 16; a++ {
			var d uint16 = 0
			d, err = in.Difference(uint16(x))
			if err != nil {
				return
			}
			dP[a][d]++
		}
	}

	return
}

func (in *Input) Difference(x uint16) (uint16, error) { // b = f(x ^ alpha) ^ f(x)

	f, err := in.Heys.RoundEncryptionBlock(x, in.Round)
	if err != nil {
		return 0, err
	}
	g, err := in.Heys.RoundEncryptionBlock(x^in.Alpha, in.Round)
	if err != nil {
		return 0, err
	}

	return f ^ g, nil
}
