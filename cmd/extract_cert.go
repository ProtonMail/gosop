package cmd

import (
	"os"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// ExtractCert - Extract a Certificate from a Secret Key
// Note that the resultant "CERTS" object will only ever contain one OpenPGP
// certificate.
func ExtractCert() error {
	// Get private key from standard input
	key, err := crypto.NewKeyFromReader(os.Stdin)
	if err != nil {
		return certErr(err)
	}
	if noArmor {
		// Unarmored I/O
		pubKey, err := key.GetPublicKey()
		if err != nil {
			return certErr(err)
		}
		if _, err := os.Stdout.Write(pubKey); err != nil {
			return certErr(err)
		}
	} else {
		// Armored I/O
		pubKey, err := key.GetArmoredPublicKey()
		if err != nil {
			return certErr(err)
		}
		if _, err := os.Stdout.WriteString(pubKey + "\n"); err != nil {
			return certErr(err)
		}
	}

	return nil
}

func certErr(err error) error {
	return Err99("extract-cert", err)
}
