package cmd

import (
	"os"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// GenerateKey creates a single default OpenPGP certificate with zero or more
// User IDs. Given that go-crypto expects name, comment, email parameters, we
// force the USERID of this implementation to be of the form "name (comment)
// <email>".
func GenerateKey(userIDs ...string) error {
	profile := utils.SelectProfile(selectedProfile)
	if profile == nil {
		return Err89
	}
	pgp := crypto.PGPWithProfile(profile)
	// Generate key
	gen := pgp.KeyGeneration()
	for _, userID := range userIDs {
		name, _, email, err := utils.ParseUserID(userID)
		if err != nil {
			return kgErr(err)
		}
		gen.AddUserId(name, email)
	}

	key, err := gen.New().GenerateKey()
	if err != nil {
		return kgErr(err)
	}
	defer key.ClearPrivateParams()

	// Lock key if required
	if keyPassword != "" {
		pw, err := utils.ReadFileOrEnv(keyPassword)
		if err != nil {
			return err
		}
		pw = []byte(strings.TrimSpace(string(pw)))
		key, err = pgp.LockKey(key, pw)
		if err != nil {
			return kgErr(err)
		}
	}

	// Output
	if noArmor {
		keyBytes, err := key.Serialize()
		if err != nil {
			return kgErr(err)
		}
		if _, err := os.Stdout.Write(keyBytes); err != nil {
			return kgErr(err)
		}
	} else {
		armored, err := key.Armor()
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
