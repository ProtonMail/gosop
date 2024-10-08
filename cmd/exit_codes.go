package cmd

import (
	"github.com/urfave/cli/v2"
)

// Error codes as defined in the draft, section 6.
var (
	Err3  = cli.Exit("Code 3: No acceptable signatures found (\"gosop verify\")", 3)
	Err13 = cli.Exit("Code 13: Asymmetric algorithm unsupported (\"gosop encrypt\")", 13)
	Err17 = cli.Exit("Code 17: Certificate not encryption-capable (\"gosop encrypt\")", 17)
	Err19 = cli.Exit("Missing required argument", 19)
	Err23 = cli.Exit("Incomplete verification instructions (\"gosop decrypt\")", 23)
	Err29 = cli.Exit("Unable to decrypt (\"gosop decrypt\")", 29)
	Err31 = cli.Exit("Non-\"UTF-8\" password (\"gosop encrypt\")", 31)
	Err37 = cli.Exit("Unsupported option", 37)
	Err41 = cli.Exit("Invalid data type (no secret key where \"KEY\" expected, etc)", 41)
	Err53 = cli.Exit("Non-text input where text expected", 53)
	Err67 = cli.Exit("A KEYS input is password-protected (locked), and sop cannot unlock it with any of the --with-key-password options", 67)
	Err69 = cli.Exit("Unsupported subcommand", 69)
	Err83 = cli.Exit("Options were supplied that are incompatible with each other", 83)
	Err89 = cli.Exit("The requested profile is unsupported or the indicated subcommand does not accept profiles", 89)
)

// Err99 returns the error message of any error not defined by the draft.
func Err99(cmd string, err error) error {
	return cli.Exit(cmd+": "+err.Error(), 99)
}
