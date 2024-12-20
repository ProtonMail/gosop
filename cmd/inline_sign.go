package cmd

import (
	"io/ioutil"
	"os"
	"unicode/utf8"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	var pw []byte
	if keyPassword != "" {
		pw, err = utils.ReadSanitizedPassword(keyPassword)
		if err != nil {
			return inlineSignErr(err)
		}
	}
	keyRing, failUnlock, err := utils.CollectKeysPassword(pw, keyFilenames...)
	if failUnlock {
		return Err67
	}
	if err != nil {
		return inlineSignErr(err)
	}
	if keyRing.CountEntities() == 0 {
		return Err41
	}
	defer keyRing.ClearPrivateParams()
	pgp := crypto.PGP()
	builder := pgp.Sign().SigningKeys(keyRing)

	// Message
	var messageBytes []byte
	if messageBytes, err = ioutil.ReadAll(os.Stdin); err != nil {
		return inlineSignErr(err)
	}

	if (asType == clearsignedOpt || asType == textOpt) && !utf8.Valid(messageBytes) {
		return Err53
	}

	if noArmor && asType == clearsignedOpt {
		return Err83
	}

	encoding := crypto.Armor
	if noArmor {
		encoding = crypto.Bytes
	}

	if asType == clearsignedOpt {
		signer, _ := builder.Utf8().New()
		signedMessage, err := signer.SignCleartext(messageBytes)
		if err != nil {
			return inlineSignErr(err)
		}
		if _, err = os.Stdout.Write(append(signedMessage, byte('\n'))); err != nil {
			return inlineSignErr(err)
		}
	} else if asType == textOpt {
		signer, _ := builder.Utf8().New()
		signedMessage, err := signer.Sign(messageBytes, encoding)
		if err != nil {
			return inlineSignErr(err)
		}
		if _, err = os.Stdout.Write(append(signedMessage, byte('\n'))); err != nil {
			return inlineSignErr(err)
		}
	} else {
		signer, _ := builder.New()
		signedMessage, err := signer.Sign(messageBytes, encoding)
		if err != nil {
			return inlineSignErr(err)
		}
		if _, err = os.Stdout.Write(append(signedMessage, byte('\n'))); err != nil {
			return inlineSignErr(err)
		}
	}
	return nil
}

func inlineSignErr(err error) error {
	return Err99("inline-sign", err)
}
