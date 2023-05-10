package cmd

import (
	"os"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// GenerateKey creates a single default OpenPGP certificate with zero or more
// User IDs. Given that go-crypto expects name, comment, email parameters, we
// force the USERID of this implementation to be of the form "name (comment)
// <email>", and we use strictly 1 USERID per generated key.
func GenerateKey(userIDs ...string) error {
	// Parse first userID
	var name, email string
	if len(userIDs) > 0 {
		var err error
		name, _, email, err = utils.ParseUserID(userIDs[0])
		if err != nil {
			return kgErr(err)
		}
	}

	// Generate x25519 key
	rsaKey, err := crypto.GenerateKey(name, email, "x25519", 256)
	if err != nil {
		return kgErr(err)
	}

	// Output
	if noArmor {
		keyBytes, err := rsaKey.Serialize()
		if err != nil {
			return kgErr(err)
		}
		if _, err := os.Stdout.Write(keyBytes); err != nil {
			return kgErr(err)
		}
	} else {
		armored, err := rsaKey.Armor()
		if err != nil {
			return kgErr(err)
		}
		_, err = os.Stdout.WriteString(armored + "\n")
		if err != nil {
			return kgErr(err)
		}
	}

	return nil
}

func kgErr(err error) error {
	return Err99("generate-key", err)
}
