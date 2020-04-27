package cmd

import (
	"io/ioutil"
	"os"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Sign takes the data from stdin and signs it with the key passed as argument.
// TODO: Exactly one signature will be made by each supplied "KEY".
func Sign(keyFilenames ...string) error {
	if len(keyFilenames) == 0 {
		println("Please provide keys to create detached signature")
		return Err19
	}

	// Signer keyring
	var keyRing *crypto.KeyRing
	var err error
	keyRing, err = utils.CollectKeys(keyFilenames...)
	if err != nil {
		return signErr(err)
	}
	if keyRing.CountEntities() == 0 {
		return Err41
	}

	// Message
	var plaintextBytes []byte
	if plaintextBytes, err = ioutil.ReadAll(os.Stdin); err != nil {
		return signErr(err)
	}
	var text bool
	if asType == textOpt {
		text = true
	}
	message := &crypto.PlainMessage{Data: plaintextBytes, TextType: text}

	// Sign
	var signature *crypto.PGPSignature
	if signature, err = keyRing.SignDetached(message); err != nil {
		return signErr(err)
	}

	if noArmor {
		if _, err = os.Stdout.Write(signature.Data); err != nil {
			return signErr(err)
		}
	} else {
		var armored string
		if armored, err = signature.GetArmored(); err != nil {
			return signErr(err)
		}
		if _, err = os.Stdout.WriteString(armored + "\n"); err != nil {
			return signErr(err)
		}
	}
	return nil
}

func signErr(err error) error {
	return Err99("sign", err)
}
