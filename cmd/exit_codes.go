package cmd

import (
	"github.com/urfave/cli/v2"
)

// Error codes as defined in the draft, section 6.
var (
	Err3  = cli.Exit("Code 3: No acceptable signatures found (\"sop-go verify\")", 3)
	Err13 = cli.Exit("Code 13: Asymmetric algorithm unsupported (\"sop-go encrypt\")", 13)
	Err17 = cli.Exit("Code 17: Certificate not encryption-capable (\"sop-go encrypt\")", 17)
	Err19 = cli.Exit("Missing required argument", 19)
	Err23 = cli.Exit("Incomplete verification instructions (\"sop-go decrypt\")", 23)
	Err29 = cli.Exit("Unable to decrypt (\"sop-go decrypt\")", 29)
	Err31 = cli.Exit("Non-\"UTF-8\" password (\"sop-go encrypt\")", 31)
	Err37 = cli.Exit("Unsupported option", 37)
	Err41 = cli.Exit("Invalid data type (no secret key where \"KEY\" expected, etc)", 41)
	Err53 = cli.Exit("Non-text input where text expected", 53)
	Err69 = cli.Exit("Unsupported subcommand", 69)
)

// Err99 returns the error message of any error not defined by the draft.
func Err99(cmd string, err error) error {
	return cli.Exit(cmd+": "+err.Error(), 99)
}
