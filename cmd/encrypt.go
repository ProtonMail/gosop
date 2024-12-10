package cmd

import (
	"io"
	"bufio"
	"os"
	"unicode"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/urfave/cli/v2"
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
	pgp := crypto.PGPWithProfile(profile.PgpProfile)
	builder := pgp.Encryption()
	var err error
	var input io.Reader = os.Stdin

	if signWith.Value() != nil {
		// GopenPGP signs automatically if an unlocked private key is passed.
		var privKeyRing *crypto.KeyRing
		var pw []byte
		if keyPassword != "" {
			pw, err = utils.ReadSanitizedPassword(keyPassword)
			if err != nil {
				return encErr(err)
			}
		}
		keys := utils.CollectFilesFromCliSlice(signWith.Value())
		privKeyRing, failUnlock, err := utils.CollectKeysPassword(pw, keys...)
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
		input = &checkUtf8Reader{
			input: *bufio.NewReader(input),
		}
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

// checkUtf8Reader checks whether the input is valid UTF-8, and exits
// with an error if not.
type checkUtf8Reader struct {
	input bufio.Reader
}

func (cr *checkUtf8Reader) Read(buf []byte) (n int, err error) {
	for n + 4 < len(buf) { // Space for at least one more rune
		r, size, err := cr.input.ReadRune()
		if err != nil {
			return n, err
		}
		if r == unicode.ReplacementChar && size == 1 { // Invalid rune
			return n, Err53
		}
		err = cr.input.UnreadRune()
		if err != nil {
			return n, err
		}
		bytesRead, err := cr.input.Read(buf[n:n+size])
		n += bytesRead
		if err != nil {
			return n, err
		}
	}
	return
}

func encErr(err error) error {
	if ec, ok := err.(cli.ExitCoder); ok {
		return ec
	}
	return Err99("encrypt", err)
}
