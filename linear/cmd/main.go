package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"

	"github.com/mariiatuzovska/cryptanalysis/heys"
	"github.com/mariiatuzovska/cryptanalysis/linear"
	"github.com/urfave/cli"
)

var (
	alpha       = 0xc00
	beta        = 0x1111
	limKeyCount = 12000
	keyFiles    = []string{}
)

func main() {

	app := cli.NewApp()
	app.Name = "linear"
	app.Usage = "linear cryptanalysis of Heys cipher command line client"
	app.Description = "linear cryptanalysis of Heys cipher"
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
				data, err := ioutil.ReadFile("community/cipher.txt")
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
			Usage: "search for linear approximations",
			Action: func(c *cli.Context) error {
				m := linear.Search()
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile("community/approximations.json", arr, os.ModePerm)
			},
		},
		{
			Name:  "show",
			Usage: "shows approximations that has been found",
			Action: func(c *cli.Context) error {
				approximations := make(map[int]map[int]float64)
				file, err := ioutil.ReadFile("community/approximations.json")
				if err != nil {
					return err
				}
				err = json.Unmarshal(file, &approximations)
				if err != nil {
					return err
				}
				fmt.Println("\nFound approximations:\n")
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
				for j := len(probs) - 1; j > -1; j-- {
					aprox := sortedMap[probs[j]]
					for alpha, beta := range aprox {
						fmt.Println(fmt.Sprintf("0x%04x -- 0x%04x -- %f -- #%d", alpha, beta, probs[j], len(probs)-j))
					}
				}

				return nil
			},
		},
		{
			Name:  "attack",
			Usage: "finds keys for all approximation alpha and beta in community/approximations.json",
			Action: func(c *cli.Context) error {
				m := linear.Attack()
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile(fmt.Sprintf("community/keys_attack_all.json"), arr, os.ModePerm)
			},
		},
		{
			Name:  "keys",
			Usage: "shows keys that has been found for some aplpha and beta",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name: "file",
				},
			},
			Action: func(c *cli.Context) error {
				keys := make(map[int]int)
				var fileName string
				if c.String("file") != "" {
					fileName = c.String("file")
				} else {
					fileName = fmt.Sprintf("community/keys_attack_all.json")
				}
				file, err := ioutil.ReadFile(fileName)
				if err != nil {
					log.Fatal(err)
				}
				err = json.Unmarshal(file, &keys)
				if err != nil {
					log.Fatal(err)
				}
				newMap := make(map[int]int)
				sortedCounts := make([]int, 0)
				for Key, count := range keys {
					if count > limKeyCount {
						// fmt.Println(fmt.Sprintf("0x%04x - %d", Key, count))
						sortedCounts = append(sortedCounts, count)
						newMap[count] = Key
					}
				}
				sort.Ints(sortedCounts)

				for i := len(sortedCounts) - 1; i > -1; i-- {
					fmt.Println(fmt.Sprintf("0x%04x - %d", newMap[sortedCounts[i]], sortedCounts[i]))
				}

				return nil
			},
		},
	}

	app.Run(os.Args)
}
