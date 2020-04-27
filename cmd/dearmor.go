package cmd

import (
	"io"
	"os"

	"golang.org/x/crypto/openpgp/armor"
)

// DearmorComm takes armored OpenPGP material from Std input and outputs the
// same material with ASCII-armoring removed.
func DearmorComm() error {
	block, err := armor.Decode(os.Stdin)
	if err != nil {
		return dearmErr(err)
	}
	_, err = io.Copy(os.Stdout, block.Body)
	if err != nil {
		return dearmErr(err)
	}

	return nil
}

func dearmErr(err error) error {
	return Err99("dearmor", err)
}
