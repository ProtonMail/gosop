package cmd

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	pgp := crypto.PGP()

	// Collect keyring
	keyRing, err := utils.CollectKeys(input...)
	if err != nil {
		return inlineVerErr(err)
	}
	builder := pgp.Verify().VerifyKeys(keyRing)

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
		if result.HasSignatureError() {
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
		result, err := verifier.Verify(nil, signatureBytes)
		if err != nil {
			return inlineVerErr(err)
		}
		if result.HasSignatureError() {
			return Err3
		}
		_, err = os.Stdout.WriteString(string(result.Result()))
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
	var ver string
	outputVerFile, err := os.Create(verificationsOut)
	if err != nil {
		return err
	}
	if result.HasSignatureError() {
		return nil
	}
	var mode string
	signType := result.SignedWithType()
	if signType == packet.SigTypeText {
		mode = "mode:text"
	} else {
		mode = "mode:binary"
	}
	creationTime := result.SignatureCreationTime()
	fingerprintSign := result.SignedByFingerprint()
	fingerprintPrimarySign, err := hex.DecodeString(result.SignedByKey().GetFingerprint())
	if err != nil {
		return err
	}
	ver = utils.VerificationString(
		time.Unix(creationTime, 0),
		fingerprintSign,
		fingerprintPrimarySign,
		mode,
	)
	if _, err = outputVerFile.WriteString(ver + "\n"); err != nil {
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
