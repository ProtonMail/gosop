package cmd

import (
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/armor"
)

// DearmorComm takes armored OpenPGP material from Std input and outputs the
// same material with ASCII-armoring removed.
func DearmorComm() error {
	inputReader, isArmored := armor.IsPGPArmored(os.Stdin)
	if !isArmored {
		// If already dearmored, output directly and return
		_, err := io.Copy(os.Stdout, inputReader)
		if err != nil {
			return dearmErr(err)
		}
		return nil
	}

	armorReader, err := armor.ArmorReader(inputReader)
	if err != nil {
		return dearmErr(err)
	}
	_, err = io.Copy(os.Stdout, armorReader)
	if err != nil {
		return dearmErr(err)
	}
	return nil
}

func dearmErr(err error) error {
	return Err99("dearmor", err)
}
