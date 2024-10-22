package cmd

import (
	"github.com/ProtonMail/gosop/utils"
	"github.com/urfave/cli/v2"
)

// Variables defined by flags
var (
	backend          bool
	extended         bool
	noArmor          bool
	sopSpec          bool
	sopv             bool
	asType           string
	notBefore        string
	notAfter         string
	password         string
	signWith         cli.StringSlice
	sessionKey       string
	sessionKeyOut    string
	verificationsOut string
	verifyWith       cli.StringSlice
	label            string
	selectedProfile  string
	keyPassword      string
)

// All possible flags for commands
var (
	backendFlag = &cli.BoolFlag{
		Name:        "backend",
		Value:       false,
		Destination: &backend,
	}
	extendedFlag = &cli.BoolFlag{
		Name:        "extended",
		Value:       false,
		Destination: &extended,
	}
	noArmorFlag = &cli.BoolFlag{
		Name:        "no-armor",
		Value:       false,
		Destination: &noArmor,
	}
	sopSpecFlag = &cli.BoolFlag{
		Name:        "sop-spec",
		Value:       false,
		Destination: &sopSpec,
	}
	sopvFlag = &cli.BoolFlag{
		Name:        "sopv",
		Value:       false,
		Destination: &sopv,
	}
	asFlag = &cli.StringFlag{
		Name:        "as",
		Value:       "binary",
		Usage:       "--as={binary|text}",
		Destination: &asType,
	}
	asSignedFlag = &cli.StringFlag{
		Name:        "as",
		Value:       "binary",
		Usage:       "--as={binary|text|clearsigned}",
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
	signWithFlag = &cli.StringSliceFlag{
		Name:        "sign-with",
		Usage:       "[--sign-with=KEY..]",
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
	verificationsOutFlag = &cli.StringFlag{
		Name:        "verifications-out",
		Aliases:     []string{"verify-out"},
		Usage:       "--verify-out=VERIFICATIONS",
		Destination: &verificationsOut,
	}
	verifyWithFlag = &cli.StringSliceFlag{
		Name:        "verify-with",
		Usage:       "[--verify-out=CERTS...]",
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
	selectedProfileFlag = &cli.StringFlag{
		Name:        "profile",
		Value:       utils.DefaultProfileName,
		Usage:       "--profile=PROFILE",
		Destination: &selectedProfile,
	}
	keyPasswordFlag = &cli.StringFlag{
		Name:        "with-key-password",
		Usage:       "--with-key-password=PASSWORD",
		Destination: &keyPassword,
	}
)
