package main

import (
	"github.com/ProtonMail/gosop/cmd"
	"log"
	"os"
	"sort"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "gosop",
		Usage: "Stateless OpenPGP implementation for GopenPGP",
		Authors: []*cli.Author{
			&cli.Author{
				Name: "Proton Technologies AG",
			},
		},
		Commands: cmd.All,
		Action: func(c *cli.Context) error {
			return nil
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
