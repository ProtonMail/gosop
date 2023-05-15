// Package cmd defines all commands for the gosop implementation.
package cmd

import (
	"github.com/urfave/cli/v2"
)

// All commands defined by the CLI.
var All = []*cli.Command{
	{
		Name:  "version",
		Usage: "Version Information",
		Flags: []cli.Flag{
			backendFlag,
			extendedFlag,
		},
		Action: func(c *cli.Context) error {
			return Version()
		},
	},
	{
		Name:      "generate-key",
		Usage:     "Generate a Secret Key",
		UsageText: "gosop generate-key [command options] [USERID...]",
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
		UsageText: "gosop extract-cert [command options]",
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
		UsageText: "gosop sign [command options] KEY [KEY...] < DATA",
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
		UsageText: "gosop verify SIGNATURE CERTS [CERTS...] < DATA",
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
		UsageText: "gosop encrypt [command options] [CERTS...] < DATA",
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
		UsageText: "gosop decrypt [command options] [KEY...] < CIPHERTEXT",
		Flags: []cli.Flag{
			sessionKeyOutFlag,
			sessionKeyFlag,
			passwordFlag,
			verificationsOutFlag,
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
		UsageText: "gosop armor [command options] < DATA",
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
		UsageText: "gosop dearmor < DATA",
		Action: func(c *cli.Context) error {
			return DearmorComm()
		},
	},
}
