package cmd

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Decrypt takes the data from stdin and decrypts it with the key file passed as
// argument, or a passphrase in a file passed with the --with-password flag.
// Note: Can't encrypt both symmetrically (passphrase) and keys.
// TODO: Multiple signers?
//
// --session-key-out=file flag: Outputs session key byte stream to given file.
// About --with-session-key flag: This is not currently supported and could be
// achieved with openpgp.packet, taking the first packet.EncryptedDataPacket
// (be it Sym. Encrypted or AEAD Encrypted) and then decrypt directly.
func Decrypt(keyFilenames ...string) error {
	if len(keyFilenames) == 0 && password == "" && sessionKey == "" {
		println("Please provide decryption keys, session key, or passphrase")
		return Err69
	}

	plaintextBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return decErr(err)
	}
	if password != "" {
		return passwordDecrypt(plaintextBytes)
	}
	privKeyRing, err := utils.CollectKeys(keyFilenames...)
	if err != nil {
		return decErr(err)
	}

	ciphertext, err := crypto.NewPGPMessageFromArmored(string(plaintextBytes))
	if err != nil {
		// If that fails, try binary
		ciphertext = crypto.NewPGPMessage(plaintextBytes)
	}

	split, err := ciphertext.SeparateKeyAndData(0, 0)
	if err != nil {
		return decErr(err)
	}

	sk, err := privKeyRing.DecryptSessionKey(split.GetBinaryKeyPacket())
	if err != nil {
		return decErr(err)
	}
	if sessionKeyOut != "" {
		err := writeSessionKeyToFile(sk)
		if err != nil {
			return decErr(err)
		}
	}
	if sessionKey != "" {
		return sessionKeyDecrypt(split.GetBinaryDataPacket())
	}

	var pubKeyRing *crypto.KeyRing
	if verifyWith != "" {
		pubKeyRing, err = utils.CollectKeys([]string{verifyWith}...)
		if err != nil {
			return decErr(err)
		}
	}

	message, err := privKeyRing.Decrypt(ciphertext, pubKeyRing, crypto.GetUnixTime())
	if err != nil {
		return decErr(err)
	}

	if _, err = os.Stdout.Write(message.Data); err != nil {
		return decErr(err)
	}

	if verifyOut != "" {
		// TODO: This is fake
		if err := writeVerificationToFile(pubKeyRing); err != nil {
			return err
		}
	}
	return nil
}

func decErr(err error) error {
	return Err99("decrypt", err)
}

func passwordDecrypt(input []byte) error {
	pw, err := utils.ReadFileOrEnv(password)
	if err != nil {
		return err
	}
	pw = []byte(strings.TrimSpace(string(pw)))
	message, err := crypto.NewPGPMessageFromArmored(string(input))
	if err != nil {
		return decErr(err)
	}
	sk, err := crypto.DecryptSessionKeyWithPassword(message.GetBinary(), pw)
	if err != nil {
		return decErr(err)
	}
	if sessionKeyOut != "" {
		err := writeSessionKeyToFile(sk)
		if err != nil {
			return decErr(err)
		}
	}
	decrypted, err := crypto.DecryptMessageWithPassword(message, pw)
	if err != nil {
		return decErr(err)
	}
	_, err = os.Stdout.WriteString(decrypted.GetString())
	return err
}

var symKeyAlgos = map[packet.CipherFunction]string{
	packet.Cipher3DES:   constants.ThreeDES,
	packet.CipherCAST5:  constants.CAST5,
	packet.CipherAES128: constants.AES128,
	packet.CipherAES192: constants.AES192,
	packet.CipherAES256: constants.AES256,
}

func sessionKeyDecrypt(dataBytes []byte) error {
	formattedSessionKey, err := utils.ReadFileOrEnv(sessionKey)
	if err != nil {
		return err
	}
	parts := strings.Split(string(formattedSessionKey), ":")
	sessionKeyAlgo, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return err
	}
	sessionKeyAlgoName, ok := symKeyAlgos[packet.CipherFunction(sessionKeyAlgo)]
	if !ok {
		return errors.New("unsupported session key algorithm")
	}
	sessionKeyBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return err
	}
	sessionKey := crypto.NewSessionKeyFromToken(sessionKeyBytes, sessionKeyAlgoName)
	plaintext, err := sessionKey.Decrypt(dataBytes)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext.Data)
	return err
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

func writeVerificationToFile(pubKeyRing *crypto.KeyRing) error {
	fgp, err := hex.DecodeString(pubKeyRing.GetKeys()[0].GetFingerprint())
	if err != nil {
		return decErr(err)
	}
	ver := utils.VerificationString(time.Now(), fgp, fgp)
	outputVerFile, err := os.Create(verifyOut)
	if err != nil {
		return decErr(err)
	}
	if _, err = outputVerFile.WriteString(ver + "\n"); err != nil {
		return decErr(err)
	}
	if err = outputVerFile.Close(); err != nil {
		return decErr(err)
	}
	return nil
}
