package main

import (
	"io/ioutil"
	"os"

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

	p := make([]int, 0x10000)
	for i := 0; i < 0x10000; i++ {
		p[i] = i
	}
	c := heys.ConvertBlocksToData(p)
	ioutil.WriteFile("community/plain.txt", c, os.ModePerm)

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
	}

	app.Run(os.Args)
}
