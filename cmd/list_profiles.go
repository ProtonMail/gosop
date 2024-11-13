package cmd

import (
	"fmt"
	"strings"

	"github.com/ProtonMail/gosop/utils"
)

const encryptCommand = "encrypt"
const keyGenCommand = "generate-key"

func ListProfiles(commands ...string) error {
	if len(commands) < 1 {
		return Err89
	}
	command := commands[0]
	switch command {
	case keyGenCommand:
		if err := printProfiles(utils.KeyGenerationProfiles); err != nil {
			listProfileErr(err)
		}
	case encryptCommand:
		if err := printProfiles(utils.EncryptionProfiles); err != nil {
			listProfileErr(err)
		}
	default:
		return Err89
	}
	return nil
}

func printProfiles(profiles []*utils.SopProfile) error {
	for id, profile := range profiles {
		aliases := ""
		if len(profile.Names) > 2 {
			aliases = fmt.Sprintf(" (aliases: %s)", strings.Join(profile.Names[1:], ", "))
		} else if len(profile.Names) > 1 {
			aliases = fmt.Sprintf(" (alias: %s)", profile.Names[1])
		}
		_, err := fmt.Printf("%s: %s%s\n", profile.Names[0], profile.Description, aliases)
		if err != nil {
			return listProfileErr(err)
		}
		if id > 2 {
			break
		}
	}
	return nil
}

func listProfileErr(err error) error {
	return Err99("list_profiles", err)
}
