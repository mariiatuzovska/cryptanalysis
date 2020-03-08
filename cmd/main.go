package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mariiatuzovska/cryptanalysis/attack"
	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/mariiatuzovska/cryptanalysis/heys"
	"github.com/mariiatuzovska/cryptanalysis/util"
	"github.com/urfave/cli"
)

var cliMapFlag map[string]cli.Flag = map[string]cli.Flag{
	"key": cli.StringFlag{
		Name:  "key",
		Usage: "path to key file",
		Value: "community/key.txt",
	},
	"gen": cli.StringFlag{
		Name:  "gen",
		Usage: "set true(t), if wants to generate new",
		Value: "f",
	},
	"show": cli.StringFlag{
		Name:  "show",
		Usage: "prints key in formats: bin, hex, octets",
	},
	"message": cli.StringFlag{
		Name:  "message",
		Usage: "path to message file",
		Value: "community/message.txt",
	},
	"cipher": cli.StringFlag{
		Name:  "cipher",
		Usage: "path to cipher file",
		Value: "community/cipher.txt",
	},
	"text": cli.StringFlag{
		Name:  "text",
		Usage: "change message file content",
	},
	"list": cli.StringFlag{
		Name:  "list",
		Usage: "path to list file",
		Value: "community/list.json",
	},
}

func main() {

	app := cli.NewApp()
	app.Name = "cryptanalysis"
	app.Usage = "cryptanalysis pkg for Heys cipher command line client"
	app.Description = "linear & differential cryptanalysis for Heys cipher"
	app.Version = "0.0.1"
	app.Copyright = "2020, mariiatuzovska"
	app.Authors = []cli.Author{cli.Author{Name: "Tuzovska Mariia"}}
	app.Commands = []cli.Command{
		{
			Name:    "key",
			Aliases: []string{"k", "keygen", "kgen"},
			Usage:   "Generating or showing key for Heys cipher",
			Action:  keygen,
			Flags: []cli.Flag{
				cliMapFlag["key"],
				cliMapFlag["gen"],
				cliMapFlag["show"],
			},
		},
		{
			Name:    "encrypt",
			Aliases: []string{"e", "enc"},
			Usage:   "Encrypt file using Heys cipher",
			Action:  encrypt,
			Flags: []cli.Flag{
				cliMapFlag["message"],
				cliMapFlag["key"],
				cliMapFlag["cipher"],
				cliMapFlag["text"],
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d", "dec"},
			Usage:   "Decrypt file using Heys cipher",
			Action:  decrypt,
			Flags: []cli.Flag{
				cliMapFlag["message"],
				cliMapFlag["key"],
				cliMapFlag["cipher"],
				cliMapFlag["text"],
			},
		},
		{
			Name:    "differential-attack",
			Aliases: []string{"diffattack", "difattack", "dattack", "da"},
			Usage:   "Differential attack",
			Action:  differentialAttack,
			Flags: []cli.Flag{
				cliMapFlag["key"],
			},
		},
		{
			Name:    "differential-search",
			Aliases: []string{"differential", "diff", "dif"},
			Usage:   "Differential search for some input alpha",
			Action:  differentialSearch,
			Flags: []cli.Flag{
				cliMapFlag["key"],
				cliMapFlag["list"],
			},
		},
		{
			Name:    "differential-table",
			Aliases: []string{"diftab", "dtab"},
			Usage:   "Creating differential probability table",
			Action:  dPTable,
			Flags: []cli.Flag{
				cliMapFlag["key"],
			},
		},
		{
			Name:    "gen-textpair",
			Aliases: []string{"gent", "gtext", "gpairs"},
			Usage:   "Generating text pairs using Heys cipher",
			Action:  genTextPair,
			Flags: []cli.Flag{
				cliMapFlag["key"],
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
	h := heys.New(c.String("key"))
	d := differential.New(h)
	gamma := d.DifferentialSearch()
	a, err := json.MarshalIndent(gamma, "", "	")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.String("list"), a, os.ModePerm)
}

func dPTable(c *cli.Context) error {
	h := heys.New(c.String("key"))
	d := differential.New(h)
	table := d.DifferentialProbabilityRoutine()
	table.SaveTable(c.String("dPTable"))
	return nil
}

func genTextPair(c *cli.Context) error {
	h := heys.New(c.String("key"))
	t := attack.NewTextPairs(h)
	t.SaveTextPairs(c.String("textPairs"))
	return nil
}

func differentialAttack(c *cli.Context) error {
	h := heys.New(c.String("key"))
	d := differential.New(h)
	//t, err := attack.NewTextPairsFromFile(c.String("textPairs"))
	//if err != nil {
	//	log.Fatal(err)
	//}
	a := attack.New(h, d)
	a.SelectDifferentials()

	return nil
}
