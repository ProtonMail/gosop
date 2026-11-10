package cmd

import (
	"bytes"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
		if len(key.Value()) == 0 {
			println("Please provide a certificate or key (--with-key)")
			return Err19
		}
	}
	timeFrom, timeTo, err := utils.ParseDates(notBefore, notAfter)
	if err != nil {
		return verErr(err)
	}
	pgp := crypto.PGP()
	builder := pgp.Verify()

	// Collect keyring
	keyRing, err := utils.CollectKeys(false, input[1:]...)
	if err != nil {
		return verErr(err)
	}
	builder.VerificationKeys(keyRing)
	if key.Value() != nil {
		var pw []byte
		if keyPassword != "" {
			pw, err = utils.ReadSanitizedPassword(keyPassword)
			if err != nil {
				return verErr(err)
			}
		}

		privKeyRing, failUnlock, err := utils.CollectKeysPassword(false, pw, key.Value()...)
		if failUnlock {
			return Err67
		}
		if err != nil {
			return verErr(err)
		}
		for _, privKey := range privKeyRing.GetKeys() {
			builder.VerificationKey(privKey)
		}
	}

	verifier, err := builder.New()
	if err != nil {
		return verErr(err)
	}

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
		issuerFingerprint := signature.Signature.IssuerFingerprint
		if issuerFingerprint == nil {
			issuerFingerprint = signature.SignedBy.GetFingerprintBytes()
		}
		issuerPrimaryFingerprint := signature.SignedBy.GetFingerprintBytes()
		ver = utils.VerificationString(
			creationTime,
			issuerFingerprint,
			issuerPrimaryFingerprint,
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
