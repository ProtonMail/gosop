package cmd

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// InlineDetach splits signatures from an inline-signed message.
func InlineDetach() error {
	pgp := crypto.PGP()

	// Create empty keyring
	keyRing, err := crypto.NewKeyRing(nil)
	if err != nil {
		return inlineDetachErr(err)
	}
	builder := pgp.Verify().
		VerificationKeys(keyRing)

	signatureBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return inlineDetachErr(err)
	}

	signature := string(signatureBytes)
	if strings.HasPrefix(signature, "-----BEGIN PGP SIGNED MESSAGE-----") {
		// handle cleartext
		verifier, _ := builder.New()
		result, err := verifier.VerifyCleartext(signatureBytes)
		if err != nil {
			return inlineDetachErr(err)
		}
		_, err = os.Stdout.WriteString(string(result.Cleartext()))
		if err != nil {
			return inlineDetachErr(err)
		}
		if err := writeSignaturesToFileFromResult(&result.VerifyResult); err != nil {
			return inlineDetachErr(err)
		}
	} else {
		verifier, _ := builder.New()
		result, err := verifier.VerifyInline(signatureBytes, crypto.Auto)
		if err != nil {
			return inlineDetachErr(err)
		}
		_, err = os.Stdout.WriteString(string(result.Bytes()))
		if err != nil {
			return inlineDetachErr(err)
		}
		if err := writeSignaturesToFileFromResult(&result.VerifyResult); err != nil {
			return inlineDetachErr(err)
		}
	}
	return err
}

func writeSignaturesToFileFromResult(result *crypto.VerifyResult) error {
	outputSigsFile, err := os.Create(signaturesOut)
	if err != nil {
		return err
	}
	defer outputSigsFile.Close()
	var buf bytes.Buffer
	for _, sig := range result.Signatures {
		if err = sig.Signature.Serialize(&buf); err != nil {
			return inlineDetachErr(err)
		}
	}
	if noArmor {
		if _, err = outputSigsFile.Write(buf.Bytes()); err != nil {
			return inlineDetachErr(err)
		}
	} else {
		armored, err := armor.ArmorPGPSignature(buf.Bytes())
		if err != nil {
			return inlineDetachErr(err)
		}
		if _, err = outputSigsFile.WriteString(armored); err != nil {
			return inlineDetachErr(err)
		}
	}
	if err = outputSigsFile.Close(); err != nil {
		return err
	}
	return nil
}

func inlineDetachErr(err error) error {
	return Err99("inline-detach", err)
}
