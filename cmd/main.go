package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/urfave/cli"
)

// 0xd00 : 0x1111 -- 0.001114
// 0xc00 : 0x1111 -- 0.001563
// 0xc00 : 0x8888 -- 0.001145
// 0xf00 : 0x1111 -- 0.001237
// 0xa00 : 0x1111 -- 0.001083
// 0xb00 : 0x1111 -- 0.001043
// 0x400 : 0x8888 -- 0.001120
// 0x400 : 0x1111 -- 0.001446

var (
	alpha    = 0xc00
	beta     = 0x1111
	keyFiles = []string{
		"community/keys_attack_0xc00_0x1111.json",
	}
)

func main() {

	app := cli.NewApp()
	app.Name = "differential"
	app.Usage = "differential cryptanalysis of Heys cipher command line client"
	app.Description = "differential cryptanalysis ofa Heys cipher"
	app.Version = "0.0.1"
	app.Copyright = "2020, mariiatuzovska"
	app.Authors = []cli.Author{cli.Author{Name: "Tuzovska Mariia"}}
	app.Commands = []cli.Command{
		{
			Name:  "diff-search",
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
			Name:  "diff-show",
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
							fmt.Println(fmt.Sprintf("0x%x : 0x%x -- %f", alpha, beta, prob))
						}
					}
				}
				return nil
			},
		},
		{
			Name:  "diff-attack",
			Usage: "finds keys for differentials alpha and beta",
			Action: func(c *cli.Context) error {
				m := differential.Attack(alpha, beta)
				// fmt.Println(fmt.Sprintf("Found key 0x%x", key))
				// return nil
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile(fmt.Sprintf("community/keys_attack_0x%x_0x%x.json", alpha, beta), arr, os.ModePerm)
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
					fileName = fmt.Sprintf("community/keys_attack_0x%x_0x%x.json", alpha, beta)
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
					fmt.Println(fmt.Sprintf("%x - %d", Key, count))
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
					if _, exist := k[0xb262]; exist {
						fmt.Println(fPath)
					}
					for key, count := range k {
						if _, exist := keys[key]; exist {
							// fmt.Println(fmt.Sprintf("existed 0x%x = %d + %d", key, keys[key], count))
							keys[key] = keys[key] + count

						} else {
							keys[key] = count
						}
					}
				}
				for Key, count := range keys {
					if count > 25 {
						fmt.Println(fmt.Sprintf("%x - %d", Key, count))
					}
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}
