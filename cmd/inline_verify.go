package cmd

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// InlineVerify checks the validity of a signed message against a set of certificates.
func InlineVerify(input ...string) error {
	if len(input) == 0 {
		println("Please provide a certificate (public key)")
		return Err19
	}

	timeFrom, timeTo, err := utils.ParseDates(notBefore, notAfter)
	if err != nil {
		return inlineVerErr(err)
	}
	pgp := crypto.PGP()

	// Collect keyring
	keyRing, err := utils.CollectKeys(input...)
	if err != nil {
		return inlineVerErr(err)
	}
	builder := pgp.Verify().
		VerificationKeys(keyRing).
		EnableStrictMessageParsing()

	signatureBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return inlineVerErr(err)
	}

	signature := string(signatureBytes)
	if strings.HasPrefix(signature, "-----BEGIN PGP SIGNED MESSAGE-----") {
		// handle cleartext
		verifier, _ := builder.New()
		result, err := verifier.VerifyCleartext(signatureBytes)
		if err != nil {
			return inlineVerErr(err)
		}
		result.ConstrainToTimeRange(timeFrom.Unix(), timeTo.Unix())
		if result.SignatureError() != nil {
			return Err3
		}
		_, err = os.Stdout.WriteString(string(result.Cleartext()))
		if err != nil {
			return inlineVerErr(err)
		}
		if verificationsOut != "" {
			if err := writeVerificationToFileFromResult(&result.VerifyResult); err != nil {
				return inlineVerErr(err)
			}
		}
	} else {
		verifier, _ := builder.New()
		result, err := verifier.VerifyInline(signatureBytes, crypto.Auto)
		if err != nil {
			return inlineVerErr(err)
		}
		result.ConstrainToTimeRange(timeFrom.Unix(), timeTo.Unix())
		if result.SignatureError() != nil {
			return Err3
		}
		_, err = os.Stdout.WriteString(string(result.Bytes()))
		if err != nil {
			return inlineVerErr(err)
		}
		if verificationsOut != "" {
			if err := writeVerificationToFileFromResult(&result.VerifyResult); err != nil {
				return inlineVerErr(err)
			}
		}
	}
	return err
}

func writeVerificationToFileFromResult(result *crypto.VerifyResult) error {
	outputVerFile, err := os.Create(verificationsOut)
	if err != nil {
		return err
	}
	defer outputVerFile.Close()
	if err = writeVerificationToOutput(outputVerFile, result); err != nil {
		return err
	}
	if err = outputVerFile.Close(); err != nil {
		return err
	}
	return nil
}

func inlineVerErr(err error) error {
	return Err99("inline-verify", err)
}
