package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Sign takes the data from stdin and signs it with the key passed as argument.
// TODO: Exactly one signature will be made by each supplied "KEY".
func Sign(keyFilenames ...string) error {
	if len(keyFilenames) == 0 {
		println("Please provide keys to create detached signature")
		return Err19
	}
	pgp := crypto.PGP()

	// Signer keyring
	var keyRing *crypto.KeyRing
	var err error
	var pw []byte
	if keyPassword != "" {
		pw, err = utils.ReadFileOrEnv(keyPassword)
		if err != nil {
			return err
		}
		pw = []byte(strings.TrimSpace(string(pw)))
	}
	keyRing, failUnlock, err := utils.CollectKeysPassword(pw, keyFilenames...)
	if failUnlock {
		return Err67
	}
	if err != nil {
		return signErr(err)
	}
	if keyRing.CountEntities() == 0 {
		return Err41
	}
	defer keyRing.ClearPrivateParams()
	builder := pgp.Sign().SigningKeys(keyRing).Detached()

	// Prepare sign
	if asType == textOpt {
		builder.UTF8()
	}

	if !noArmor {
		builder.Armor()
	}

	// Sign
	signer, _ := builder.New()
	ptWriter, err := signer.SigningWriter(os.Stdout, nil)
	if err != nil {
		return signErr(err)
	}
	_, err = io.Copy(ptWriter, os.Stdin)
	if err != nil {
		return signErr(err)
	}
	err = ptWriter.Close()
	if err != nil {
		return signErr(err)
	}

	if !noArmor {
		if _, err = os.Stdout.WriteString("\n"); err != nil {
			return signErr(err)
		}
	}
	return nil
}

func signErr(err error) error {
	return Err99("sign", err)
}
