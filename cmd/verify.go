package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func BeforeVerify(c *cli.Context) error {
	switch c.Args().Len() {
	case 0:
		return Err3
	case 1:
		fmt.Fprintln(os.Stderr, "Please provide a certificate (public key)")
		return Err19
	}
	_, _, err := utils.ParseDates(notBefore, notAfter)
	if err != nil {
		return verErr(err)
	}
	return nil
}

// Verify checks the validity of a signature against a set of certificates.
func Verify(input ...string) error {
	timeFrom, timeTo, err := utils.ParseDates(notBefore, notAfter)
	if err != nil {
		return verErr(err)
	}
	pgp := crypto.PGP()

	// Collect keyring
	keyRing, err := utils.CollectKeys(input[1:]...)
	if err != nil {
		return verErr(err)
	}
	verifier, _ := pgp.Verify().
		VerificationKeys(keyRing).
		New()

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

	dataReader, err := verifier.VerifyingReader(os.Stdin, bytes.NewReader(signature), crypto.Auto)
	if err != nil {
		return verErr(err)
	}
	result, err := dataReader.DiscardAllAndVerifySignature()
	if err != nil {
		return verErr(err)
	}
	result.ConstrainToTimeRange(timeFrom.Unix(), timeTo.Unix())
	if result.SignatureError() != nil {
		return Err3
	}
	if err = writeVerificationToOutput(os.Stdout, result); err != nil {
		return verErr(err)
	}
	return err
}

func writeVerificationToOutput(out *os.File, result *crypto.VerifyResult) error {
	var ver string
	if result.SignatureError() != nil {
		return nil
	}
	for _, signature := range result.Signatures {
		if signature.SignatureError != nil || signature.Signature == nil {
			continue
		}
		var mode string
		signType := signature.Signature.SigType
		if signType == packet.SigTypeText {
			mode = "mode:text"
		} else {
			mode = "mode:binary"
		}
		creationTime := signature.Signature.CreationTime
		fingerprintSign := signature.SignedBy.GetFingerprintBytes()
		fingerprintPrimarySign := signature.SignedBy.GetFingerprintBytes()
		ver = utils.VerificationString(
			creationTime,
			fingerprintSign,
			fingerprintPrimarySign,
			mode,
		)
		if _, err := out.WriteString(ver + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func verErr(err error) error {
	return Err99("verify", err)
}
