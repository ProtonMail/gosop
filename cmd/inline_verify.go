package cmd

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// InlineVerify checks the validity of a signed message against a set of certificates.
func InlineVerify(input ...string) error {
	if len(input) == 0 {
		println("Please provide a certificate (public key)")
		return Err19
	}

	if notBefore != "-" || notAfter != "now" {
		println("--not-after and --not-before are not implemented.")
		return Err37
	}

	// Collect keyring
	keyRing, err := utils.CollectKeys(input...)
	if err != nil {
		return inlineVerErr(err)
	}

	signatureBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return inlineVerErr(err)
	}

	signature := string(signatureBytes)
	if !strings.Contains(signature, "-----BEGIN PGP SIGNED MESSAGE-----") {
		// Only clearsigned messages are supported for now.
		return Err37
	}

	message, err := helper.VerifyCleartextMessage(keyRing, signature, crypto.GetUnixTime())
	if err != nil {
		return inlineVerErr(err)
	}

	_, err = os.Stdout.WriteString(message)
	if err != nil {
		return inlineVerErr(err)
	}

	if verificationsOut != "" {
		// TODO: This is fake
		if err := writeVerificationToFile(keyRing); err != nil {
			return err
		}
	}

	return err
}

func inlineVerErr(err error) error {
	return Err99("inline-verify", err)
}
