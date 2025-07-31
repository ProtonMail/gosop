// Package cmd defines all commands for the gosop implementation.
package cmd

import (
	"io"

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
		Before: BeforeListProfiles,
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
			signingOnlyFlag,
		},
		Before: BeforeGenerateKey,
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
		Before: BeforeSign,
		Action: func(c *cli.Context) error {
			return Sign(c.Args().Slice()...)
		},
	},
	{
		Name:      "verify",
		Usage:     "Verify a Detached Signature",
		UsageText: "gosop verify [command options] SIGNATURE CERTS [CERTS...] < DATA",
		Flags: []cli.Flag{
			notBeforeFlag,
			notAfterFlag,
		},
		Before: BeforeVerify,
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
		Before: BeforeInlineSign,
		Action: func(c *cli.Context) error {
			return InlineSign(c.Args().Slice()...)
		},
	},
	{
		Name:      "inline-verify",
		Usage:     "Verify an Inline-Signed Message",
		UsageText: "gosop inline-verify [command options] CERTS [CERTS...] < INLINESIGNED",
		Flags: []cli.Flag{
			notBeforeFlag,
			notAfterFlag,
			verificationsOutFlag,
		},
		Before: BeforeInlineVerify,
		Action: func(c *cli.Context) error {
			return InlineVerify(c.Args().Slice()...)
		},
	},
	{
		Name:      "inline-detach",
		Usage:     "Split Signatures from an Inline-Signed Message",
		UsageText: "gosop inline-detach [command options] < INLINESIGNED",
		Flags: []cli.Flag{
			noArmorFlag,
			signaturesOutFlag,
		},
		Action: func(c *cli.Context) error {
			return InlineDetach()
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
		Before: BeforeEncrypt,
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
		Before: BeforeDecrypt,
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
	{
		Name:      "supports",
		Usage:     "Check whether gosop supports the given subcommand and options",
		UsageText: "gosop supports COMMAND",
		Action: func(c *cli.Context) error {
			for _, c := range c.App.Commands {
				c.Action = func(ctx *cli.Context) error {
					return nil // Don't run the actual action.
				}
			}
			c.App.Writer = io.Discard // Discard help text.
			args := []string{"gosop"}
			args = append(args, c.Args().Slice()...)
			return c.App.Run(args)
		},
	},
}
