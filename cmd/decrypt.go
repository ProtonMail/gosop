package cmd

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
)

var symKeyAlgos = map[packet.CipherFunction]string{
	packet.Cipher3DES:   constants.ThreeDES,
	packet.CipherCAST5:  constants.CAST5,
	packet.CipherAES128: constants.AES128,
	packet.CipherAES192: constants.AES192,
	packet.CipherAES256: constants.AES256,
}

// Decrypt takes the data from stdin and decrypts it with the key file passed as
// argument, or a passphrase in a file passed with the --with-password flag.
// Note: Can't encrypt both symmetrically (passphrase) and keys.
// TODO: Multiple signers?
//
// --session-key-out=file flag: Outputs session key byte stream to given file.
func Decrypt(keyFilenames ...string) error {
	if len(keyFilenames) == 0 && password == "" && sessionKey == "" {
		println("Please provide decryption keys, session key, or passphrase")
		return Err69
	}
	var err error

	pgp := crypto.PGP()
	builder := pgp.Decryption()

	var pubKeyRing *crypto.KeyRing
	if verifyWith != "" {
		pubKeyRing, err = utils.CollectKeys([]string{verifyWith}...)
		if err != nil {
			return decErr(err)
		}
		builder.VerifyKeys(pubKeyRing)
	}
	if (verificationsOut == "" && pubKeyRing.CountEntities() != 0) ||
		(verificationsOut != "" && pubKeyRing.CountEntities() == 0) {
		return Err23
	}

	var sk *crypto.SessionKey
	if sessionKey != "" {
		sk, err = parseSessionKey()
		if err != nil {
			return decErr(err)
		}
		builder.SessionKey(sk)
	} else if password != "" {
		pw, err := utils.ReadFileOrEnv(password)
		if err != nil {
			return decErr(err)
		}
		pw = []byte(strings.TrimSpace(string(pw)))
		builder.Password(pw)
	} else {
		var pw []byte
		if keyPassword != "" {
			pw, err = utils.ReadSanitizedPassword(keyPassword)
			if err != nil {
				return decErr(err)
			}
		}
		privKeyRing, failUnlock, err := utils.CollectKeysPassword(pw, keyFilenames...)
		if failUnlock {
			return Err67
		}
		if err != nil {
			return decErr(err)
		}
		defer privKeyRing.ClearPrivateParams()
		builder.DecryptionKeys(privKeyRing)
	}

	if sessionKeyOut != "" {
		builder.RetrieveSessionKey()
	}

	decryptor, _ := builder.New()
	ptReader, err := decryptor.DecryptingReader(os.Stdin)
	if err != nil {
		return decErr(err)
	}
	_, err = io.Copy(os.Stdout, ptReader)
	if err != nil {
		return decErr(err)
	}

	if sessionKeyOut != "" {
		err = writeSessionKeyToFile(ptReader.SessionKey())
		if err != nil {
			return decErr(err)
		}
	}

	if verificationsOut != "" {
		result, err := ptReader.VerifySignature()
		if err != nil {
			return decErr(err)
		}
		if err := writeVerificationToFileFromResult(result); err != nil {
			return decErr(err)
		}
	}

	return nil
}

func decErr(err error) error {
	return Err99("decrypt", err)
}

func parseSessionKey() (*crypto.SessionKey, error) {
	formattedSessionKey, err := utils.ReadFileOrEnv(sessionKey)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(string(formattedSessionKey)), ":")
	skAlgo, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, err
	}
	skAlgoName, ok := symKeyAlgos[packet.CipherFunction(skAlgo)]
	if !ok {
		return nil, errors.New("unsupported session key algorithm")
	}
	skBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	sk := crypto.NewSessionKeyFromToken(skBytes, skAlgoName)
	return sk, nil
}

func writeSessionKeyToFile(sk *crypto.SessionKey) error {
	var sessionKeyFile *os.File
	if sessionKeyOut[0:4] == "@FD:" {
		fd, err := strconv.ParseUint(sessionKeyOut[4:], 10, strconv.IntSize)
		if err != nil {
			return err
		}
		sessionKeyFile = os.NewFile(uintptr(fd), sessionKeyOut)
	} else {
		var err error
		sessionKeyFile, err = os.Create(sessionKeyOut)
		if err != nil {
			return err
		}
	}
	cipherFunc, err := sk.GetCipherFunc()
	if err != nil {
		return decErr(err)
	}
	formattedSessionKey := strconv.FormatUint(uint64(cipherFunc), 10) + ":" +
		strings.ToUpper(hex.EncodeToString(sk.Key))
	if _, err = sessionKeyFile.Write([]byte(formattedSessionKey)); err != nil {
		return decErr(err)
	}
	if err = sessionKeyFile.Close(); err != nil {
		return decErr(err)
	}
	return nil
}
