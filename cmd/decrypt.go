package cmd

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
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

	err = handleSessionKeys(split.GetBinaryKeyPacket(), privKeyRing)
	if err != nil {
		return decErr(err)
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
	plaintext, err := helper.DecryptMessageWithPassword(pw, string(input))
	if err != nil {
		return decErr(err)
	}
	_, err = os.Stdout.WriteString(plaintext)
	return err
}

func sessionKeyDecrypt(dataBytes []byte) error {
	token, err := utils.ReadFileOrEnv(sessionKey)
	if err != nil {
		return err
	}
	sessionKey := crypto.NewSessionKeyFromToken(token, constants.AES256)
	plaintext, err := sessionKey.Decrypt(dataBytes)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext.Data)
	return err
}

func writeSessionKeyToFile(privKeyRing *crypto.KeyRing, keyBytes []byte) error {
	rawSK, err := privKeyRing.DecryptSessionKey(keyBytes)
	if err != nil {
		return decErr(err)
	}
	sessionKeyFile, err := os.Create(sessionKeyOut)
	if err != nil {
		return decErr(err)
	}
	if _, err = sessionKeyFile.Write(rawSK.Key); err != nil {
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

func handleSessionKeys(keyBytes []byte, privKR *crypto.KeyRing) error {
	// Create split message to work with session keys if flags are given
	if sessionKeyOut != "" {
		err := writeSessionKeyToFile(privKR, keyBytes)
		if err != nil {
			return err
		}
	}
	return nil
}
