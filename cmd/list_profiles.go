package cmd

import (
	"fmt"
	"os"

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
		if err := printProfiles(keyGenCommand, utils.KeyGenerationProfiles); err != nil {
			listProfileErr(err)
		}
	case encryptCommand:
		if err := printProfiles(encryptCommand, utils.EncryptionProfiles); err != nil {
			listProfileErr(err)
		}
	default:
		return Err89
	}
	return nil
}

func printProfiles(command string, profiles []string) error {
	for id, profile := range profiles {
		description := utils.GetProfileDescription(command, profile)
		_, err := os.Stdout.WriteString(fmt.Sprintf("%s: %s\n", profile, description))
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
