package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/mariiatuzovska/ciphers/heys"
	"github.com/mariiatuzovska/ciphers/util"
	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()
	app.Name = "cryptanalysis"
	app.Usage = "cryptanalysis pkg for Heys cipher command line client"
	app.Description = "linear&differential cryptanalysis for Heys cipher"
	app.Version = "0.0.1"
	app.Copyright = "2020, mariiatuzovska"
	app.Authors = []cli.Author{cli.Author{Name: "Tuzovska Mariia"}}
	app.Commands = []cli.Command{
		{
			Name:    "key",
			Aliases: []string{"k", "keygen", "kgen"},
			Usage:   "Generate key file for Heys cipher",
			Action:  keygen,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "key",
					Usage: "path to key file",
					Value: "community/key.txt",
				},
				&cli.StringFlag{
					Name:  "gen",
					Usage: "set true(t), if wants to generate new",
					Value: "f",
				},
				&cli.StringFlag{
					Name:  "show",
					Usage: "prints key in formats: bin, hex, octets",
				},
			},
		},
		{
			Name:    "encrypt",
			Aliases: []string{"e", "enc"},
			Usage:   "Encrypt file using Heys cipher",
			Action:  encrypt,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "message",
					Usage: "path to message file",
					Value: "community/message.txt",
				},
				&cli.StringFlag{
					Name:  "key",
					Usage: "path to key file",
					Value: "community/key.txt",
				},
				&cli.StringFlag{
					Name:  "cipher",
					Usage: "path to cipher file",
					Value: "community/cipher.txt",
				},
				&cli.StringFlag{
					Name:  "text",
					Usage: "change message file content",
				},
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d", "dec"},
			Usage:   "Decrypt file using Heys cipher",
			Action:  decrypt,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "message",
					Usage: "path to message file",
					Value: "community/message.txt",
				},
				&cli.StringFlag{
					Name:  "key",
					Usage: "path to key file",
					Value: "community/key.txt",
				},
				&cli.StringFlag{
					Name:  "cipher",
					Usage: "path to cipher file",
					Value: "community/cipher.txt",
				},
				&cli.StringFlag{
					Name:  "text",
					Usage: "change cipher file content",
				},
			},
		},
		{
			Name:    "differential",
			Aliases: []string{"diff", "dif"},
			Usage:   "Differential search",
			Action:  differentialSearch,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "message",
					Usage: "path to message file",
					Value: "community/message.txt",
				},
				&cli.StringFlag{
					Name:  "key",
					Usage: "path to key file",
					Value: "community/key.txt",
				},
				&cli.StringFlag{
					Name:  "cipher",
					Usage: "path to cipher file",
					Value: "community/cipher.txt",
				},
				&cli.StringFlag{
					Name:  "alpha",
					Usage: "input difference",
					Value: "5",
				},
				&cli.StringFlag{
					Name:  "quantile",
					Usage: "input quantiles separated by coma ','",
					Value: "0.1,0.05,0.01,0.005,0.002",
				},
				&cli.StringFlag{
					Name:  "round",
					Usage: "count of rounds",
					Value: "6",
				},
			},
		},
	}

	app.Run(os.Args)
}

func keygen(c *cli.Context) error {

	var key []byte
	if c.String("gen") != "f" {
		h := heys.New(c.String("key"))
		key = h.GenereKey()
		log.Printf("key bytes %x has been created and written to %s", key, h.KeyFile)
	} else {
		var err error
		key, err = util.GetBytesFromFile(c.String("key"))
		if err != nil {
			log.Fatal(err)
		}
	}
	if c.String("show") == "hex" {
		fmt.Printf("Hex value of key is %x\n", key)
	}
	if c.String("show") == "bin" {
		fmt.Printf("Binary value of key is %b\n", key)
	}
	if c.String("show") == "octet" {
		fmt.Println("Bytes of key", key)
	}
	return nil
}

func encrypt(c *cli.Context) error {

	if c.String("text") != "" {
		err := util.SetStringToFile([]byte(c.String("text")), c.String("message"))
		if err != nil {
			log.Fatal(err)
		}
	}
	content, err := util.GetBytesFromFile(c.String("message"))
	if err != nil {
		log.Fatal(err)
	}
	h := heys.New(c.String("key"))
	ct, err := h.Encrypt(content)
	if err != nil {
		log.Fatal(err)
	}
	err = util.SetStringToFile(ct, c.String("cipher"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("cipher bytes %x has been created and written to %s", ct, c.String("cipher"))

	return nil
}

func decrypt(c *cli.Context) error {

	if c.String("text") != "" {
		err := util.SetStringToFile([]byte(c.String("text")), c.String("cipher"))
		if err != nil {
			log.Fatal(err)
		}
	}
	content, err := util.GetBytesFromFile(c.String("cipher"))
	if err != nil {
		log.Fatal(err)
	}
	h := heys.New(c.String("key"))
	pt, err := h.Decrypt(content)
	if err != nil {
		log.Fatal(err)
	}
	err = util.SetStringToFile(pt, c.String("message"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("message bytes %x has been decrypted and written to %s", pt, c.String("message"))

	return nil
}

func differentialSearch(c *cli.Context) error {

	alpha, err := strconv.Atoi(c.String("alpha"))
	if err != nil {
		log.Fatal(err)
	}
	arr := strings.Split(c.String("quantile"), ",")
	quantile := make([]float32, len(arr))
	for i, v := range arr {
		x, err := strconv.ParseFloat(v, 32)
		quantile[i] = float32(x)
		if err != nil {
			log.Fatal(err)
		}
	}
	round, err := strconv.Atoi(c.String("round"))
	if err != nil {
		log.Fatal(err)
	}
	h := heys.New(c.String("key"))
	d := differential.New(h, uint16(alpha), quantile, round)
	fmt.Println(d.DifferentialSearch())

	return nil
}
