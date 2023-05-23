package cmd

import (
	"bytes"
	"os"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Verify checks the validity of a signature against a set of certificates.
func Verify(input ...string) error {
	switch len(input) {
	case 0:
		return Err3
	case 1:
		println("Please provide a certificate (public key)")
		return Err19
	}

	if notBefore != "-" || notAfter != "now" {
		println("--not-after and --not-before are not implemented.")
		return Err37
	}
	pgp := crypto.PGP()

	// Collect keyring
	keyRing, err := utils.CollectKeys(input[1:]...)
	if err != nil {
		return verErr(err)
	}
	verifier, _ := pgp.Verify().VerifyKeys(keyRing).New()

	// Collect signature
	sigBytes, err := utils.ReadFileOrEnv(input[0])
	if err != nil {
		return verErr(err)
	}
	var signature []byte
	signature, err = armor.UnarmorBytes(sigBytes)
	if err != nil {
		signature = sigBytes
	}

	dataReader, err := verifier.VerifyingReader(os.Stdin, bytes.NewReader(signature))
	if err != nil {
		return verErr(err)
	}
	result, err := dataReader.DiscardAllAndVerifySignature()
	if err != nil {
		return verErr(err)
	}
	if result.HasSignatureError() {
		return Err3
	}
	if verificationsOut != "" {
		if err := writeVerificationToFileFromResult(result); err != nil {
			return inlineVerErr(err)
		}
	}
	return err
}

func verErr(err error) error {
	return Err99("verify", err)
}
