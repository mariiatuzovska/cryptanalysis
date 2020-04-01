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

var key = []uint16{0x391a, 0xd01e, 0x1cc9, 0x467f, 0x0553, 0xc131, 0x8f42}

var (
	alpha uint16 = 0x7
	beta  uint16 = 0xfffc
)

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
			Name: "difference-new",
			Action: func(c *cli.Context) error {
				d := differential.NewDifferential(heys.NewHeys(&key))
				m := d.Search()
				arr, err := json.MarshalIndent(*m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile("community/differences.json", arr, os.ModePerm)
			},
		},
		{
			Name: "difference-show",
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
			Name: "attack",
			Action: func(c *cli.Context) error {
				d := differential.NewDifferential(heys.NewHeys(&key))
				m := d.Attack(alpha, beta)
				arr, err := json.MarshalIndent(*m, "", "	")
				if err != nil {
					log.Fatal(err)
				}
				return ioutil.WriteFile(fmt.Sprintf("community/key0x%x0x%x.json", alpha, beta), arr, os.ModePerm)
			},
		},
		{
			Name: "key",
			Action: func(c *cli.Context) error {
				fmt.Println(fmt.Sprintf("%x", key))
				return nil
			},
		},
	}

	app.Run(os.Args)
}
