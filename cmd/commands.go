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
			sopSpecFlag,
			sopvFlag,
		},
		Action: func(c *cli.Context) error {
			return Version()
		},
	},
	{
		Name:      "list-profiles",
		Usage:     "List profiles for subcommands",
		UsageText: "gosop list-profiles SUBCOMMAND",
		Flags:     []cli.Flag{},
		Action: func(c *cli.Context) error {
			return ListProfiles(c.Args().Slice()...)
		},
	},
	{
		Name:      "generate-key",
		Usage:     "Generate a Secret Key",
		UsageText: "gosop generate-key [command options] [USERID...]",
		Flags: []cli.Flag{
			noArmorFlag,
			selectedProfileFlag,
			keyPasswordFlag,
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
			keyPasswordFlag,
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
		Name:      "inline-sign",
		Usage:     "Create an Inline-Signed Message",
		UsageText: "gosop inline-sign [command options] KEY [KEY...] < DATA",
		Flags: []cli.Flag{
			noArmorFlag,
			asSignedFlag,
			keyPasswordFlag,
		},
		Action: func(c *cli.Context) error {
			return InlineSign(c.Args().Slice()...)
		},
	},
	{
		Name:      "inline-verify",
		Usage:     "Verify an Inline-Signed Message",
		UsageText: "gosop inline-verify CERTS [CERTS...] < INLINESIGNED",
		Flags: []cli.Flag{
			notBeforeFlag,
			notAfterFlag,
			verificationsOutFlag,
		},
		Action: func(c *cli.Context) error {
			return InlineVerify(c.Args().Slice()...)
		},
	},
	{
		Name:      "encrypt",
		Usage:     "Encrypt a Message",
		UsageText: "gosop encrypt [command options] [CERTS...] < DATA",
		Flags: []cli.Flag{
			selectedProfileFlag,
			asFlag,
			noArmorFlag,
			passwordFlag,
			signWithFlag,
			keyPasswordFlag,
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
			keyPasswordFlag,
		},
		Action: func(c *cli.Context) error {
			return Decrypt(c.Args().Slice()...)
		},
	},
	{
		Name:      "armor",
		Usage:     "Add ASCII Armor",
		UsageText: "gosop armor [command options] < DATA",
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
