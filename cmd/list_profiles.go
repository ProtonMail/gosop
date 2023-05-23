package cmd

import (
	"fmt"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/ProtonMail/gosop/utils"
)

var profileCommands = []string{"generate-key", "encrypt"}

func ListProfiles(commands ...string) error {
	if len(commands) < 1 {
		return Err89
	}
	command := commands[0]
	match := false
	for _, cmd := range profileCommands {
		if cmd == command {
			match = true
			break
		}
	}
	if !match {
		return Err89
	}
	profiles := profile.PresetProfiles()
	_, err := os.Stdout.WriteString("default: use the defaults\n")
	if err != nil {
		return listProfileErr(err)
	}
	for id, profile := range profiles {
		description := utils.GetProfileDescription(command, profile)
		_, err := os.Stdout.WriteString(fmt.Sprintf("%s: %s\n", profile, description))
		if err != nil {
			return listProfileErr(err)
		}
		if id > 1 {
			break
		}
	}
	return nil
}

func listProfileErr(err error) error {
	return Err99("list_profiles", err)
}
