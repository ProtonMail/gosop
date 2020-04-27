// Package cmd defines all commands for the gosop implementation.
package cmd

import (
	"os"

	"github.com/urfave/cli/v2"
)

// All commands defined by the CLI.
var All = []*cli.Command{
	{
		Name:  "version",
		Usage: "Version Information",
		Action: func(c *cli.Context) error {
			_, err := os.Stdout.WriteString("GopenPGP v2.0.1\n")
			return err
		},
	},
	{
		Name:      "generate-key",
		Usage:     "Generate a Secret Key",
		UsageText: "sop-go generate-key [command options] [USERID...]",
		Flags: []cli.Flag{
			noArmorFlag,
		},
		Action: func(c *cli.Context) error {
			return GenerateKey(c.Args().Slice()...)
		},
	},
	{
		Name:      "extract-cert",
		Usage:     "Extract a Certificate from a Secret Key",
		UsageText: "sop-go extract-cert [command options]",
		Flags: []cli.Flag{
			noArmorFlag,
		},
		Action: func(c *cli.Context) error {
			return ExtractCert()
		},
	},
	{
		Name:      "sign",
		Usage:     "Create a Detached Signature",
		UsageText: "sop-go sign [command options] KEY [KEY...] < DATA",
		Flags: []cli.Flag{
			noArmorFlag,
			asFlag,
		},
		Action: func(c *cli.Context) error {
			return Sign(c.Args().Slice()...)
		},
	},
	{
		Name:      "verify",
		Usage:     "Verify a Detached Signature",
		UsageText: "sop-go verify SIGNATURE CERTS [CERTS...] < DATA",
		Flags: []cli.Flag{
			notBeforeFlag,
			notAfterFlag,
		},
		Action: func(c *cli.Context) error {
			return Verify(c.Args().Slice()...)
		},
	},
	{
		Name:      "encrypt",
		Usage:     "Encrypt a Message",
		UsageText: "sop-go encrypt [command options] [CERTS...] < DATA",
		Flags: []cli.Flag{
			asFlag,
			noArmorFlag,
			passwordFlag,
			signWithFlag,
		},
		Action: func(c *cli.Context) error {
			return Encrypt(c.Args().Slice()...)
		},
	},
	{
		Name:      "decrypt",
		Usage:     "Decrypt a Message",
		UsageText: "sop-go decrypt [command options] [KEY...] < CIPHERTEXT",
		Flags: []cli.Flag{
			sessionKeyOutFlag,
			sessionKeyFlag,
			passwordFlag,
			verifyOutFlag,
			verifyWithFlag,
			verifyNotBeforeFlag,
			verifyNotAfterFlag,
		},
		Action: func(c *cli.Context) error {
			return Decrypt(c.Args().Slice()...)
		},
	},
	{
		Name:      "armor",
		Usage:     "Add ASCII Armor",
		UsageText: "sop-go armor [command options] < DATA",
		Flags: []cli.Flag{
			labelFlag,
		},
		Action: func(c *cli.Context) error {
			return ArmorComm(c.Args().Slice()...)
		},
	},
	{
		Name:      "dearmor",
		Usage:     "Remove ASCII Armor",
		UsageText: "sop-go dearmor < DATA",
		Action: func(c *cli.Context) error {
			return DearmorComm()
		},
	},
}
