package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/mariiatuzovska/cryptanalysis/heys"
	"github.com/urfave/cli"
)

var key = []uint16{0xa060, 0x8b55, 0x9c2f, 0x1c7f, 0x7e69, 0xc260, 0xb262}
var bKey = []byte{0xa0, 0x60, 0x8b, 0x55, 0x9c, 0x2f, 0x1c, 0x7f, 0x7e, 0x69, 0xc2, 0x60, 0xb2, 0x62}

var (
	alpha uint16 = 0xa
	beta  uint16 = 0xf4f5
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
			Name:  "e",
			Usage: "Encrypt file using Heys cipher",
			Action: func(c *cli.Context) error {
				messageContent, err := ioutil.ReadFile("community/plain.txt")
				if err != nil {
					log.Fatal(err)
				}
				blocks := heys.FormData(messageContent)
				h := heys.NewHeys(&key)
				for i := 0; i < len(blocks); i++ {
					h.EncryptBlock(&blocks[i])
				}
				ct := heys.DescribeData(&blocks)
				file, err := os.Create("community/cipher.txt")
				if err != nil {
					log.Fatal(err)
				}
				_, err = file.WriteString(string(ct))
				if err != nil {
					log.Fatal(err)
				}
				return file.Close()
			},
		},
		{
			Name:  "d",
			Usage: "Decrypt file using Heys cipher",
			Action: func(c *cli.Context) error {
				cipherContent, err := ioutil.ReadFile("community/cipher.txt")
				if err != nil {
					log.Fatal(err)
				}
				blocks := heys.FormData(cipherContent)
				h := heys.NewHeys(&key)
				for i := 0; i < len(blocks); i++ {
					h.DecryptBlock(&blocks[i])
				}
				ct := heys.DescribeData(&blocks)
				file, err := os.Create("community/plain.txt")
				if err != nil {
					log.Fatal(err)
				}
				_, err = file.WriteString(string(ct))
				if err != nil {
					log.Fatal(err)
				}
				return file.Close()
			},
		},
		{
			Name:  "key-save",
			Usage: "save key to file",
			Action: func(c *cli.Context) error {
				file, err := os.Create("community/key.txt")
				if err != nil {
					return err
				}
				_, err = file.WriteString(string(bKey))
				if err != nil {
					return err
				}
				return file.Close()
			},
		},
		{
			Name:  "diff-search",
			Usage: "search for defferentials",
			Action: func(c *cli.Context) error {
				d := differential.NewDifferential(heys.NewHeys(&key))
				m := d.Search()
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
				dPTable := make(differential.DPTable)
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
						fmt.Println(fmt.Sprintf("0x%x : 0x%x -- %f", alpha, beta, prob))
					}
				}
				return nil
			},
		},
		{
			Name:  "attack",
			Usage: "finds keys for differentials alpha and beta",
			Action: func(c *cli.Context) error {
				d := differential.NewDifferential(heys.NewHeys(&key))
				m := d.Attack(alpha, beta)
				arr, err := json.MarshalIndent(m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile(fmt.Sprintf("community/keys_attack_0x%x_0x%x.json", alpha, beta), arr, os.ModePerm)
			},
		},
		{
			Name:  "key-origin",
			Usage: "shows original key",
			Action: func(c *cli.Context) error {
				fmt.Println(fmt.Sprintf("%x", key))
				return nil
			},
		},
		{
			Name:  "key-found",
			Usage: "shows keys that has been found for some aplpha and beta",
			Action: func(c *cli.Context) error {
				keys := make(map[uint16]int)
				file, err := ioutil.ReadFile(fmt.Sprintf("community/keys_attack_0x%x_0x%x.json", alpha, beta))
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
				keyFiles := []string{
					"community/keys_attack_0x7_0xf4f5.json",
					"community/keys_attack_0x7_0xfff5.json",
					"community/keys_attack_0x3_0xf4f1.json",
					"community/keys_attack_0xa_0xf4f5.json",
				}
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
					if _, exist := k[0x31cc]; exist {
						fmt.Println(fPath)
					}
					for key, count := range k {
						if _, exist := keys[key]; exist {
							keys[key] = keys[key] + count
						} else {
							keys[key] = count
						}
					}
				}
				for Key, count := range keys {
					if count > 50 {
						fmt.Println(fmt.Sprintf("%x - %d", Key, count))
					}
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}
