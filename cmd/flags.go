package cmd

import "github.com/urfave/cli/v2"

// Variables defined by flags
var (
	noArmor       bool
	asType        string
	notBefore     string
	notAfter      string
	password      string
	signWith      string
	sessionKey    string
	sessionKeyOut string
	verifyOut     string
	verifyWith    string
	label         string
)

// All possible flags for commands
var (
	noArmorFlag = &cli.BoolFlag{
		Name:        "no-armor",
		Value:       false,
		Destination: &noArmor,
	}
	asFlag = &cli.StringFlag{
		Name:        "as",
		Value:       "binary",
		Usage:       "--as={binary|text}",
		Destination: &asType,
	}
	notBeforeFlag = &cli.StringFlag{
		Name:        "not-before",
		Value:       "-",
		Usage:       "--not-before={-|DATE}",
		Destination: &notBefore,
	}
	notAfterFlag = &cli.StringFlag{
		Name:        "not-after",
		Value:       "now",
		Usage:       "--not-after={-|DATE}",
		Destination: &notAfter,
	}
	passwordFlag = &cli.StringFlag{
		Name:        "with-password",
		Usage:       "--with-password=PASSWORD",
		Destination: &password,
	}
	signWithFlag = &cli.StringFlag{
		Name:        "sign-with",
		Usage:       "--sign-with=KEY",
		Destination: &signWith,
	}
	sessionKeyFlag = &cli.StringFlag{
		Name:        "with-session-key",
		Usage:       "--with-session-key=SESSIONKEY",
		Destination: &sessionKey,
	}
	sessionKeyOutFlag = &cli.StringFlag{
		Name:        "session-key-out",
		Usage:       "--session-key-out=SESSIONKEY",
		Destination: &sessionKeyOut,
	}
	verifyOutFlag = &cli.StringFlag{
		Name:        "verify-out",
		Usage:       "--verify-out=VERIFICATIONS",
		Destination: &verifyOut,
	}
	verifyWithFlag = &cli.StringFlag{
		Name:        "verify-with",
		Usage:       "--verify-out=CERTS",
		Destination: &verifyWith,
	}
	verifyNotBeforeFlag = &cli.StringFlag{
		Name:        "verify-not-before",
		Value:       "-",
		Usage:       "--verify-not-before={-|DATE}",
		Destination: &notBefore,
	}
	verifyNotAfterFlag = &cli.StringFlag{
		Name:        "verify-not-after",
		Value:       "now",
		Usage:       "--verify-not-after={-|DATE}",
		Destination: &notAfter,
	}
	labelFlag = &cli.StringFlag{
		Name:        "label",
		Value:       "auto",
		Usage:       "--label={auto|sig|key|cert|message}",
		Destination: &label,
	}
)
