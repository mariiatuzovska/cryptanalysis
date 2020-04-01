package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/mariiatuzovska/cryptanalysis/differential"
	"github.com/mariiatuzovska/cryptanalysis/heys"
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

	var key = []uint16{0x391a, 0xd01e, 0x1cc9, 0x467f, 0x0553, 0xc131, 0x8f42}

	d := differential.NewDifferential(heys.NewHeys(&key))
	m := d.Search()

	arr, err := json.MarshalIndent(m, "", "	")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("community/textPairs.json", arr, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	// app := cli.NewApp()
	// app.Name = "cryptanalysis"
	// app.Usage = "cryptanalysis pkg for Heys cipher command line client"
	// app.Description = "linear & differential cryptanalysis for Heys cipher"
	// app.Version = "0.0.1"
	// app.Copyright = "2020, mariiatuzovska"
	// app.Authors = []cli.Author{cli.Author{Name: "Tuzovska Mariia"}}
	// app.Commands = []cli.Command{
	// 	{
	// 		Name:    "key",
	// 		Aliases: []string{"k", "keygen", "kgen"},
	// 		Usage:   "Generating or showing key for Heys cipher",
	// 		Action:  keygen,
	// 		Flags: []cli.Flag{
	// 			cliMapFlag["key"],
	// 			cliMapFlag["gen"],
	// 			cliMapFlag["show"],
	// 		},
	// 	},
	// }

	// app.Run(os.Args)
}
