package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	profile := utils.SelectEncryptionProfile(selectedProfile)
	if profile == nil {
		return Err89
	}
	pgp := crypto.PGPWithProfile(profile)
	builder := pgp.Encryption()
	var err error
	var input io.Reader = os.Stdin

	if signWith != "" {
		// GopenPGP signs automatically if an unlocked private key is passed.
		var privKeyRing *crypto.KeyRing
		var pw []byte
		if keyPassword != "" {
			pw, err = utils.ReadSanitizedPassword(keyPassword)
			if err != nil {
				return encErr(err)
			}
		}
		privKeyRing, failUnlock, err := utils.CollectKeysPassword(pw, strings.Split(signWith, " ")...)
		if failUnlock {
			return Err67
		}
		if err != nil {
			return encErr(err)
		}
		defer privKeyRing.ClearPrivateParams()
		builder.SigningKeys(privKeyRing)
	}

	if asType == textOpt {
		builder.Utf8()
		// Expensive check
		var plaintextBytes []byte
		if plaintextBytes, err = io.ReadAll(input); err != nil {
			return encErr(err)
		}
		if !utf8.Valid(plaintextBytes) {
			return Err53
		}
		input = bytes.NewReader(plaintextBytes)
	}

	// Password encrypt
	if password != "" {
		pw, err := utils.ReadSanitizedPassword(password)
		if err != nil {
			return encErr(err)
		}
		builder.Password(pw)
	} else {
		pubKeyRing, err := utils.CollectKeys(keyFilenames...)
		if err != nil {
			return encErr(err)
		}
		builder.Recipients(pubKeyRing)
	}

	encoding := crypto.Armor
	if noArmor {
		encoding = crypto.Bytes
	}

	encryption, _ := builder.New()
	ptWriter, err := encryption.EncryptingWriter(os.Stdout, encoding)
	if err != nil {
		return encErr(err)
	}
	_, err = io.Copy(ptWriter, input)
	if err != nil {
		return encErr(err)
	}
	err = ptWriter.Close()
	if err != nil {
		return encErr(err)
	}

	if !noArmor {
		_, err = os.Stdout.WriteString("\n")
	}
	return err
}

func encErr(err error) error {
	return Err99("encrypt", err)
}
