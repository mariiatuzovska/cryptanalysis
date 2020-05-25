package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"

	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/mariiatuzovska/cryptanalysis/heys"
	"github.com/urfave/cli"
)

var (
	alpha       = 0xc00
	beta        = 0x1111
	limKeyCount = 5
	keyFiles    = []string{
		"community/keys_attack_0x0c00_0x8888.json",
		"community/keys_attack_0x0c00_0x1111.json",
		"community/keys_attack_0x0400_0x1111.json",
		"community/keys_attack_0x0400_0x8888.json",
		"community/keys_attack_0x0a00_0x1111.json",
		"community/keys_attack_0x0b00_0x1111.json",
		"community/keys_attack_0x0f00_0x1111.json",
		"community/keys_attack_0x0d00_0x1111.json",
	}
)

func main() {

	app := cli.NewApp()
	app.Name = "differential"
	app.Usage = "differential cryptanalysis of Heys cipher command line client"
	app.Description = "differential cryptanalysis of Heys cipher"
	app.Version = "0.0.1"
	app.Copyright = "2020, mariiatuzovska"
	app.Authors = []cli.Author{cli.Author{Name: "Tuzovska Mariia"}}
	app.Commands = []cli.Command{
		{
			Name:  "e",
			Usage: "encrypt",
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile("community/plain.txt")
				if err != nil {
					return err
				}
				blocks := heys.ConvertDataToBlocks(data)
				for i := 0; i < len(blocks); i++ {
					blocks[i] = heys.Encrypt(blocks[i])
				}
				data = heys.ConvertBlocksToData(blocks)
				key := heys.ConvertBlocksToData(heys.Defaultkey)
				ioutil.WriteFile("community/key.txt", key, os.ModePerm)
				return ioutil.WriteFile("community/cipher.txt", data, os.ModePerm)
			},
		},
		{
			Name:  "d",
			Usage: "decrypt",
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile("community/ct2.txt")
				if err != nil {
					return err
				}
				blocks := heys.ConvertDataToBlocks(data)
				for i := 0; i < len(blocks); i++ {
					blocks[i] = heys.Decrypt(blocks[i])
				}
				data = heys.ConvertBlocksToData(blocks)
				key := heys.ConvertBlocksToData(heys.Defaultkey)
				ioutil.WriteFile("community/key.txt", key, os.ModePerm)
				return ioutil.WriteFile("community/pt2.txt", data, os.ModePerm)
			},
		},
		{
			Name:  "search",
			Usage: "search for defferentials",
			Action: func(c *cli.Context) error {
				// d := differential.NewDifferential(heys.NewHeys(&key))
				m := differential.Search()
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile("community/differences.json", arr, os.ModePerm)
			},
		},
		{
			Name:  "show",
			Usage: "shows defferentials that has been found",
			Action: func(c *cli.Context) error {
				dPTable := make(map[int]map[int]float64)
				file, err := ioutil.ReadFile("community/differences.json")
				if err != nil {
					return err
				}
				err = json.Unmarshal(file, &dPTable)
				if err != nil {
					return err
				}
				for alpha, barnch := range dPTable {
					for beta, prob := range barnch {
						if 0x000f&beta != 0 && 0x00f0&beta != 0 && 0x0f00&beta != 0 && 0xf000&beta != 0 {
							fmt.Println(fmt.Sprintf("0x%04x : 0x%04x -- %f", alpha, beta, prob))
						}
					}
				}
				return nil
			},
		},
		{
			Name:  "attack",
			Usage: "finds keys for differentials alpha and beta",
			Action: func(c *cli.Context) error {
				m := differential.Attack(alpha, beta)
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile(fmt.Sprintf("community/keys_attack_0x%04x_0x%04x.json", alpha, beta), arr, os.ModePerm)
			},
		},
		{
			Name:  "attack-all",
			Usage: "finds keys for all differentials alpha and beta in community/differentials.json",
			Action: func(c *cli.Context) error {
				dPTable := make(map[int]map[int]float64)
				file, err := ioutil.ReadFile("community/differences.json")
				if err != nil {
					return err
				}
				err = json.Unmarshal(file, &dPTable)
				if err != nil {
					return err
				}
				for a, bMap := range dPTable {
					for b := range bMap {
						if 0x000f&b != 0 && 0x00f0&b != 0 && 0x0f00&b != 0 && 0xf000&b != 0 {
							pathToFile := fmt.Sprintf("community/keys_attack_0x%04x_0x%04x.json", a, b)
							fmt.Println(pathToFile)
							m := differential.Attack(a, b)
							arr, err := json.MarshalIndent(m, "", "	")
							if err != nil {
								log.Fatal(err)
							}
							err = ioutil.WriteFile(pathToFile, arr, os.ModePerm)
							if err != nil {
								log.Fatal(err)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:  "report",
			Usage: "shows beautiful report about differential cryptanacysis of heys cipher",
			Action: func(c *cli.Context) error {
				DPTMap := make(map[int]map[int]float64)
				file, err := ioutil.ReadFile("community/differences.json")
				if err != nil {
					return err
				}
				err = json.Unmarshal(file, &DPTMap)
				if err != nil {
					return err
				}
				fmt.Println("\nFound differences:\n")
				sortKeysDPTable := make([]int, 0)
				sortedDiffProbs := make([]float64, 0)
				sortedDiffMap := make(map[float64]int)
				for key := range DPTMap {
					if len(DPTMap[key]) > 0 {
						sortKeysDPTable = append(sortKeysDPTable, key)
					}
				}
				sort.Ints(sortKeysDPTable)
				for _, a := range sortKeysDPTable {
					differences := DPTMap[a]
					sortedDiffProbs = make([]float64, 0)
					sortedDiffMap = make(map[float64]int)
					for b, prob := range differences {
						if 0x000f&b != 0 && 0x00f0&b != 0 && 0x0f00&b != 0 && 0xf000&b != 0 {
							sortedDiffProbs = append(sortedDiffProbs, prob)
							sortedDiffMap[prob] = b
						}
					}
					sort.Float64s(sortedDiffProbs)
					for _, prob := range sortedDiffProbs {
						fmt.Println(fmt.Sprintf("0x%04x -- 0x%04x -- %f", alpha, sortedDiffMap[prob], prob))
					}

				}
				// keys
				keys := make(map[uint16]int)
				for _, fPath := range keyFiles {
					fmt.Println("\nRead file:", fPath)
					k := make(map[uint16]int)
					file, err := ioutil.ReadFile(fPath)
					if err != nil {
						log.Fatal(err)
					}
					err = json.Unmarshal(file, &k)
					if err != nil {
						log.Fatal(err)
					}
					sorted := []int{}
					sortedMap := make(map[int]uint16)
					for key, count := range k {
						if _, exist := keys[key]; exist {
							keys[key] = keys[key] + count

						} else {
							keys[key] = count
						}
						sorted = append(sorted, count)
						sortedMap[count] = key
					}
					sort.Ints(sorted)
					for i := len(sorted) - 1; i > -1; i-- {
						fmt.Println(fmt.Sprintf("%04x - %d", sortedMap[sorted[i]], sorted[i]))
					}
				}
				fmt.Println(fmt.Sprintf("\n\nSUM for all keys\n"))
				sorted := []int{}
				sortedMap := make(map[int]uint16)
				for Key, count := range keys {
					if count > limKeyCount {
						sorted = append(sorted, count)
						sortedMap[count] = Key
					}
				}
				sort.Ints(sorted)
				for i := len(sorted) - 1; i > -1; i-- {
					fmt.Println(fmt.Sprintf("%04x - %d", sortedMap[sorted[i]], sorted[i]))
				}

				return nil
			},
		},
		{
			Name:  "key-found",
			Usage: "shows keys that has been found for some aplpha and beta",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name: "file",
				},
			},
			Action: func(c *cli.Context) error {
				keys := make(map[uint16]int)
				var fileName string
				if c.String("file") != "" {
					fileName = c.String("file")
				} else {
					fileName = fmt.Sprintf("community/keys_attack_0x%04x_0x%04x.json", alpha, beta)
				}
				file, err := ioutil.ReadFile(fileName)
				if err != nil {
					log.Fatal(err)
				}
				err = json.Unmarshal(file, &keys)
				if err != nil {
					log.Fatal(err)
				}
				for Key, count := range keys {
					if count > limKeyCount {
						fmt.Println(fmt.Sprintf("0x%04x - %d", Key, count))
					}
				}

				return nil
			},
		},
		{
			Name:  "key-found-all",
			Usage: "shows keys and their probability for all differentials that has been processed",
			Action: func(c *cli.Context) error {
				keys := make(map[uint16]int)
				for _, fPath := range keyFiles {
					k := make(map[uint16]int)
					file, err := ioutil.ReadFile(fPath)
					if err != nil {
						log.Fatal(err)
					}
					err = json.Unmarshal(file, &k)
					if err != nil {
						log.Fatal(err)
					}
					for key, count := range k {
						if _, exist := keys[key]; exist {
							// fmt.Println(fmt.Sprintf("existed 0x%04x = %d + %d", key, keys[key], count))
							keys[key] = keys[key] + count

						} else {
							keys[key] = count
						}
					}
				}
				sorted := []int{}
				sortedMap := make(map[int]uint16)
				for Key, count := range keys {
					if count > limKeyCount {
						sorted = append(sorted, count)
						sortedMap[count] = Key
					}
				}
				sort.Ints(sorted)
				for i := len(sorted) - 1; i > -1; i-- {
					fmt.Println(fmt.Sprintf("%04x - %d", sortedMap[sorted[i]], sorted[i]))
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}
