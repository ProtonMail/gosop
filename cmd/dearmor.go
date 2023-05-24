package cmd

import (
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/armor"
)

// DearmorComm takes armored OpenPGP material from Std input and outputs the
// same material with ASCII-armoring removed.
func DearmorComm() error {
	armorReader, err := armor.ArmorReader(os.Stdin)
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
