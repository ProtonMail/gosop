package cmd

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"time"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
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

	// Collect keyring
	keyRing, err := utils.CollectKeys(input[1:]...)
	if err != nil {
		return verErr(err)
	}

	plaintextBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return verErr(err)
	}
	var text bool
	if asType == textOpt {
		text = true
	}
	message := &crypto.PlainMessage{Data: plaintextBytes, TextType: text}

	// Collect signature
	sigBytes, err := utils.ReadFileOrEnv(input[0])
	if err != nil {
		return verErr(err)
	}
	var signature *crypto.PGPSignature
	signature, err = crypto.NewPGPSignatureFromArmored(string(sigBytes))
	if err != nil {
		signature = crypto.NewPGPSignature(sigBytes)
	}

	if err = keyRing.VerifyDetached(message, signature, 0); err != nil {
		return Err3
	}

	// TODO: This is fake
	fgp, err := hex.DecodeString(keyRing.GetKeys()[0].GetFingerprint())
	if err != nil {
		return verErr(err)
	}
	ver := utils.VerificationString(time.Now(), fgp, fgp)
	_, err = os.Stdout.WriteString(ver + "\n")

	return err
}

func verErr(err error) error {
	return Err99("verify", err)
}
