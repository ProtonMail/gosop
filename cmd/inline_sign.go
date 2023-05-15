package cmd

import (
	"io/ioutil"
	"os"
	"unicode/utf8"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

const (
	clearsignedOpt = "clearsigned"
)

// InlineSign takes the data from stdin and signs it with the key passed as argument.
// TODO: Exactly one signature should be made by each supplied "KEY".
func InlineSign(keyFilenames ...string) error {
	if len(keyFilenames) == 0 {
		println("Please provide keys to create detached signature")
		return Err19
	}

	// Signer keyring
	var keyRing *crypto.KeyRing
	var err error
	keyRing, err = utils.CollectKeys(keyFilenames...)
	if err != nil {
		return inlineSignErr(err)
	}
	if keyRing.CountEntities() == 0 {
		return Err41
	}

	// Message
	var messageBytes []byte
	if messageBytes, err = ioutil.ReadAll(os.Stdin); err != nil {
		return inlineSignErr(err)
	}
	if !utf8.Valid(messageBytes) {
		return Err53
	}
	message := string(messageBytes)

	if asType == clearsignedOpt {
		signedMessage, err := helper.SignCleartextMessage(keyRing, message)
		if err != nil {
			return inlineSignErr(err)
		}
		if _, err = os.Stdout.WriteString(signedMessage + "\n"); err != nil {
			return inlineSignErr(err)
		}
	} else {
		// TODO: Support --as={binary|text}, and not just --as=clearsigned.
		return Err37
	}
	return nil
}

func inlineSignErr(err error) error {
	return Err99("inline-sign", err)
}
