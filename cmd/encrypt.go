package cmd

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

const (
	textOpt = "text"
)

// Encrypt takes the data from stdin and encrypts it with the keys passed as
// argument, or a passphrase passed with the --with-password flag. It signs
// with the given private keys.
// Note: Can't encrypt both symmetrically (passphrase) and keys.
func Encrypt(keyFilenames ...string) error {
	if len(keyFilenames) == 0 && password == "" {
		println("Please provide recipients and/or passphrase (--with-password)")
		return Err19
	}
	var err error
	var plaintextBytes []byte
	if plaintextBytes, err = ioutil.ReadAll(os.Stdin); err != nil {
		return encErr(err)
	}

	// Password encrypt
	var pgpMessage *crypto.PGPMessage
	if password != "" {
		pw := []byte(strings.TrimSpace(password))
		ciphertext, err := helper.EncryptMessageWithPassword(pw, string(plaintextBytes))
		if err != nil {
			return encErr(err)
		}
		_, err = os.Stdout.WriteString(ciphertext + "\n")
		return err
	}

	message := &crypto.PlainMessage{
		Data:     plaintextBytes,
		TextType: asType == textOpt}

	pubKeyRing, err := utils.CollectKeys(keyFilenames...)
	if err != nil {
		return encErr(err)
	}

	if signWith != "" {
		// GopenPGP signs automatically if an unlocked private key is passed.
		var privKeyRing *crypto.KeyRing
		privKeyRing, err = utils.CollectKeys(strings.Split(signWith, " ")...)
		if err != nil {
			return encErr(err)
		}
		defer privKeyRing.ClearPrivateParams()
		pgpMessage, err = pubKeyRing.Encrypt(message, privKeyRing)
		if err != nil {
			return encErr(err)
		}
	} else {
		pgpMessage, err = pubKeyRing.Encrypt(message, nil)
		if err != nil {
			return encErr(err)
		}
	}

	if noArmor {
		_, err = os.Stdout.Write(pgpMessage.GetBinary())
	} else {
		armored, errArm := pgpMessage.GetArmored()
		if errArm != nil {
			return encErr(errArm)
		}
		_, err = os.Stdout.WriteString(armored + "\n")
	}
	return err
}

func encErr(err error) error {
	return Err99("encrypt", err)
}
