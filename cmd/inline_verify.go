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
	if len(input) == 0 && len(key.Value()) == 0 {
		println("Please provide a certificate or key (--with-key)")
		return Err19
	}

	timeFrom, timeTo, err := utils.ParseDates(notBefore, notAfter)
	if err != nil {
		return inlineVerErr(err)
	}
	pgp := crypto.PGP()
	builder := pgp.Verify()

	// Collect keyring
	keyRing, err := utils.CollectKeys(false, input...)
	if err != nil {
		return inlineVerErr(err)
	}
	builder.VerificationKeys(keyRing)
	if key.Value() != nil {
		var pw []byte
		if keyPassword != "" {
			pw, err = utils.ReadSanitizedPassword(keyPassword)
			if err != nil {
				return inlineVerErr(err)
			}
		}

		privKeyRing, failUnlock, err := utils.CollectKeysPassword(false, pw, key.Value()...)
		if failUnlock {
			return Err67
		}
		if err != nil {
			return inlineVerErr(err)
		}
		for _, privKey := range privKeyRing.GetKeys() {
			builder.VerificationKey(privKey)
		}
	}

	verifier, err := builder.New()
	if err != nil {
		return inlineVerErr(err)
	}

	signatureBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return inlineVerErr(err)
	}

	signature := string(signatureBytes)
	if strings.HasPrefix(signature, "-----BEGIN PGP SIGNED MESSAGE-----") {
		// handle cleartext
		result, err := verifier.VerifyCleartext(signatureBytes)
		if err != nil {
			return inlineVerErr(err)
		}
		result.ConstrainToTimeRange(timeFrom.Unix(), timeTo.Unix())
		if result.SignatureError() != nil {
			return Err3
		}
		_, err = os.Stdout.Write(result.Cleartext())
		if err != nil {
			return inlineVerErr(err)
		}
		if verificationsOut != "" {
			if err := writeVerificationToFileFromResult(&result.VerifyResult); err != nil {
				return inlineVerErr(err)
			}
		}
	} else {
		result, err := verifier.VerifyInline(signatureBytes, crypto.Auto)
		if err != nil {
			return inlineVerErr(err)
		}
		result.ConstrainToTimeRange(timeFrom.Unix(), timeTo.Unix())
		if result.SignatureError() != nil {
			return Err3
		}
		_, err = os.Stdout.Write(result.Bytes())
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
	outputVerFile, err := utils.OpenOutFile(verificationsOut)
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
